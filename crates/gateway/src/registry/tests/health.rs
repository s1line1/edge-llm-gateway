//! registry 测试：心跳新鲜度与“注册数 vs 可路由数”的可观测性契约。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 可观测性契约：**注册条目数**与**可路由数**必须能分开看。
///
/// 失联 agent 的条目要等连接真正关闭才摘除，所以 `len()` 会把它算作"在线"，
/// 而 `try_acquire` 会把它过滤掉。两者混为一谈时，"所有请求 503"会被误读成
/// "agent 掉了"——线上排查正是卡在这里（/metrics 显示 2 个 agent，实际全部 stale）。
#[tokio::test]
async fn healthy_count_separates_registered_from_routable() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    let fresh = reg.register("fresh".into(), IP, vec!["*".into()], 4, c1.clone());
    reg.register("stale".into(), IP, vec!["*".into()], 4, c2.clone());

    let stale_after = Duration::from_millis(30);
    tokio::time::sleep(Duration::from_millis(50)).await;
    // 两条都过期
    assert_eq!(reg.len(), 2, "条目仍在注册表里（连接没关）");
    assert_eq!(reg.healthy_count(stale_after), 0, "但没有一条可路由");
    let st = reg.status(stale_after);
    assert_eq!((st.registered, st.healthy), (2, 0));
    assert!(st.oldest_last_seen_ago.unwrap() >= Duration::from_millis(50));
    assert!(matches!(
        reg.try_acquire(stale_after, "qwen2.5"),
        Err(AcquireError::NoAgent)
    ));

    // 一条心跳恢复 → 只有它可路由
    assert!(reg.heartbeat_if_same("fresh", IP, fresh));
    assert_eq!(reg.len(), 2);
    assert_eq!(reg.healthy_count(stale_after), 1);
    assert_eq!(reg.status(stale_after).healthy, 1);
    assert!(reg.try_acquire(stale_after, "qwen2.5").is_ok());

    // 空注册表：两个数都是 0，且没有 last_seen 可报
    let empty = Registry::default();
    assert_eq!(empty.healthy_count(stale_after), 0);
    assert_eq!(empty.status(stale_after).registered, 0);
    assert!(empty.status(stale_after).oldest_last_seen_ago.is_none());
}

#[tokio::test]
async fn heartbeat_refreshes_stale_entry() {
    let reg = Registry::default();
    let conn = test_connection().await;
    let h = reg.register("h".into(), IP, vec!["*".into()], 4, conn.clone());
    // 30ms 后仍按 10ms 判定失联
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        reg.try_acquire(Duration::from_millis(10), "qwen2.5"),
        Err(AcquireError::NoAgent)
    ));
    // 心跳刷新 last_seen → 恢复可用
    assert!(reg.heartbeat_if_same("h", IP, h));
    assert!(reg
        .try_acquire(Duration::from_millis(100), "qwen2.5")
        .is_ok());
    // 对不存在的 agent 心跳 → 无害
    assert!(!reg.heartbeat_if_same("ghost", IP, 0));

    // 别的连接的 stable_id → 也不刷新（这就是本次修的那条：帧里的 id 不足以证明"你是谁"）
    assert!(!reg.heartbeat_if_same("h", IP, h.wrapping_add(1)));
}

/// 规格（2026-10-07 修复）：**心跳只对"本连接注册的那条条目"生效**。
///
/// 修复前 `heartbeat(agent_id)` 只按帧里自报的 id 查全表，于是任何持合法证书的 agent 都能用
/// 别人的 id 替一条**已经死掉**的条目续命——网关会持续把请求路由到那台机器，而且日志里没有
/// 任何痕迹（不像顶替会打 `duplicate agent connection`）。
#[tokio::test]
async fn a_heartbeat_only_refreshes_the_connection_that_registered_the_agent() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    let victim = reg.register("victim".into(), IP, vec!["*".into()], 4, c1.clone());
    let attacker = reg.register("attacker".into(), IP, vec!["*".into()], 4, c2.clone());
    assert_ne!(victim, attacker, "前提：两条连接拿到不同的 stable_id");

    let stale_after = Duration::from_millis(10);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(reg.healthy_count(stale_after), 0, "前提：两条都已过期");

    // 攻击者用自己的连接、发 victim 的 id 的心跳 → **不得**刷新（stable_id 对不上）
    assert!(
        !reg.heartbeat_if_same("victim", IP, attacker),
        "另一条连接的 stable_id 不该刷新 victim"
    );
    assert_eq!(reg.healthy_count(stale_after), 0, "victim 应仍是 stale");

    // victim 自己的连接发心跳 → 刷新
    assert!(
        reg.heartbeat_if_same("victim", IP, victim),
        "本连接的 stable_id 应当刷新"
    );
    assert_eq!(reg.healthy_count(stale_after), 1, "victim 恢复可路由");
}
