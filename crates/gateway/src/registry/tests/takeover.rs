//! registry 测试：同名同来源重连时的接管与排空。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（D3，**接管必须优雅**）：同名同来源重连时，旧连接**不得**被立刻关掉——那条连接上
/// 可能还有"请求帧已完整送达上游、模型正在生成"的在途请求，立刻关就是纯损失。旧连接要等
/// 在途归零（或宽限到期）才关。
///
/// 观测手段：`s2n-quic` 的连接句柄在关闭后**仍能回答 `remote_addr()`**（实测过：close 之后
/// 依旧 `Ok`），所以"关没关"无法从连接本身观测。这里用 `register_with_grace` 的关闭通知
/// （`crate::evict_close::CloseObserver`，生产路径永远传 `None`）把关闭事件转成可等待的信号，
/// 并**记数**：通知必须恰好来一次。
///
/// 变异验证：① 把接管改回"立刻 close" ⇒ 第一条断言红；② 新条目不再继承旧条目的在途计数器
/// ⇒ 也会红（drain 轮询的是旧计数器，而新条目从 0 起算）。
#[tokio::test]
async fn a_takeover_drains_in_flight_requests_before_closing_the_old_connection() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;

    let reg = Registry::default();
    let old_sid = reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );

    // 占住旧连接的一个在途槽位，模拟"已经送达上游、模型正在生成"
    let (held, slot) = reg.try_acquire(Duration::from_secs(30), "m").unwrap();
    assert_eq!(held.stable_id, old_sid);
    let entry = |reg: &Registry| {
        reg.inner
            .read()
            .unwrap()
            .get(&AgentKey::new("edge", IP))
            .map(|e| e.inflight.load(AtomicOrdering::Relaxed))
    };
    assert_eq!(entry(&reg), Some(1), "槽位已占住");

    let closed = Arc::new(AtomicBool::new(false));
    let close_count = Arc::new(AtomicUsize::new(0));
    let notify = {
        let closed = closed.clone();
        let count = close_count.clone();
        Arc::new(move || {
            closed.store(true, AtomicOrdering::SeqCst);
            count.fetch_add(1, AtomicOrdering::SeqCst);
        }) as crate::evict_close::CloseObserver
    };

    // 同一 (id, ip) 重连 → 接管。此刻键上还有 1 个在途请求（**不是**本次接管调用自己的）。
    let new_sid = reg.register_with_grace(
        "edge".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
        GRACE,
        Some(notify),
    );
    assert_ne!(old_sid, new_sid);
    assert_eq!(reg.len(), 1, "条目已换成新连接（旧连接移出路由）");
    assert_eq!(
        entry(&reg),
        Some(1),
        "新条目必须**继承**在途计数：换连接不等于在途请求消失（否则 drain 立刻放行）"
    );

    // ① 在途未归零时必须保持开着（观察窗口 500ms，远短于 GRACE=5s）
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !closed.load(AtomicOrdering::SeqCst),
        "旧连接还有在途请求时不得被关闭（否则那一半请求白做）"
    );
    assert_eq!(close_count.load(AtomicOrdering::SeqCst), 0);

    // ② 释放槽位 → 旧连接应在宽限内被关，且只关一次
    drop(slot);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while !closed.load(AtomicOrdering::SeqCst) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        closed.load(AtomicOrdering::SeqCst),
        "在途归零后旧连接必须被关闭（否则它成了自认为在线的僵尸）"
    );
    assert_eq!(close_count.load(AtomicOrdering::SeqCst), 1, "只关一次");
}

/// 规格：接管一条**空闲**旧连接时立刻关（不因走 drain 路径而白白延后一个 tick）。
///
/// 为什么单独钉：`defer_close` 即使 `inflight == 0` 也是异步的，而"空闲接管"是最常见的
/// 形态（agent 重连时旧连接上通常没有请求），它的关闭时机不该被改成"下一个调度点"。
#[tokio::test]
async fn a_takeover_of_an_idle_connection_closes_it_right_away() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::Arc;

    let reg = Registry::default();
    let old_conn = test_connection().await;
    reg.register("edge".into(), IP, vec!["m".into()], 4, old_conn);

    let closed = Arc::new(AtomicBool::new(false));
    let notify = {
        let closed = closed.clone();
        Arc::new(move || closed.store(true, AtomicOrdering::SeqCst))
            as crate::evict_close::CloseObserver
    };
    reg.register_with_grace(
        "edge".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
        GRACE,
        Some(notify),
    );
    assert!(
        closed.load(AtomicOrdering::SeqCst),
        "空闲旧连接必须在接管当刻同步关闭（这条路径不走 defer_close）"
    );
}
