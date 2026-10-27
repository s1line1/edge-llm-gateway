//! registry 测试：选路规则的次序、模型过滤与错误变体。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（评估 §8 passB）：选路规则的**次序**——精确声明 > `*` 通配，同级负载轻者优先；
/// 排除/过期各自把候选滤空时要给出正确的那一种错误。
///
/// 规则现在是纯函数 [`pick`]，所以这条测试直接用条目断言，不必再绕 `try_acquire` 的占位副作用
/// （要造的负载直接用条目上的原子量写，测试与 `Entry` 同模块）。
#[tokio::test]
async fn pick_orders_exact_over_wildcard_then_lightest() {
    let reg = Registry::default();
    let stale = Duration::from_secs(10);
    reg.register(
        "wild".into(),
        IP,
        vec!["*".into()],
        8,
        test_connection().await,
    );
    let exact = reg.register(
        "exact".into(),
        IP,
        vec!["m".into()],
        8,
        test_connection().await,
    );
    let busy = reg.register(
        "exact-busy".into(),
        IP,
        vec!["m".into()],
        8,
        test_connection().await,
    );

    // 直接给"忙"那条写负载：两条精确里它更重，所以应排在 exact 之后
    let inner = reg.inner.read().unwrap();
    inner
        .values()
        .find(|e| e.stable_id == busy)
        .unwrap()
        .inflight
        .store(2, Ordering::Relaxed);

    let ordered: Vec<&str> = pick(inner.values(), now_millis(), stale, "m", &[])
        .unwrap()
        .iter()
        .map(|e| e.agent_id.as_str())
        .collect();
    assert_eq!(
        ordered,
        vec!["exact", "exact-busy", "wild"],
        "精确声明必须排在通配之前，同级负载轻者优先；实际 {ordered:?}"
    );

    // 排掉两条精确的 → 只剩通配
    let only_wild = pick(inner.values(), now_millis(), stale, "m", &[exact, busy]).unwrap();
    assert_eq!(
        only_wild
            .iter()
            .map(|e| e.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["wild"]
    );

    // 全部过期 → NoAgent（没人可用）
    assert!(matches!(
        pick(inner.values(), now_millis(), Duration::ZERO, "m", &[]),
        Err(AcquireError::NoAgent)
    ));
}

/// 规格：**有人但没有一个声明这个模型** → `NoModel`（调用方据此回 404/400 而不是 503）。
///
/// 单独一条测试是刻意的：`NoModel` 需要一份**没有 `*` 通配者**的表（通配者在，任何模型
/// 都能被服务），而 `pick` 的读锁不能跨 `await`（clippy `await_holding_lock`），
/// 混在选路次序那条测试里会既难读又踩 lint。
#[tokio::test]
async fn pick_reports_no_model_when_none_declares_it() {
    let reg = Registry::default();
    reg.register(
        "only-m".into(),
        IP,
        vec!["m".into()],
        8,
        test_connection().await,
    );
    let inner = reg.inner.read().unwrap();
    assert!(matches!(
        pick(
            inner.values(),
            now_millis(),
            Duration::from_secs(10),
            "other",
            &[]
        ),
        Err(AcquireError::NoModel)
    ));
}

#[tokio::test]
async fn try_acquire_filters_by_model() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    let c3 = test_connection().await;
    reg.register(
        "qwen-edge".into(),
        IP,
        vec!["qwen2.5".into()],
        1, // 容量 1：打满后验证回落通配
        c1.clone(),
    );
    reg.register(
        "llama-edge".into(),
        IP,
        vec!["llama3".into()],
        4,
        c2.clone(),
    );
    // 通配 edge：任何模型都可路由到它
    reg.register("wildcard-edge".into(), IP, vec!["*".into()], 4, c3.clone());

    // qwen2.5 → 精确声明的 qwen-edge 优先于仅通配的 wildcard-edge，
    // 绝不能是 llama-edge
    let (e, s) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    let id = {
        let inner = reg.inner.read().unwrap();
        inner
            .iter()
            .find(|(_, v)| v.stable_id == e.stable_id)
            .map(|(k, _)| k.agent_id.clone())
            .unwrap()
    };
    assert_eq!(id, "qwen-edge", "exact model match must win over wildcard");
    drop(s);

    // llama3 → 精确声明的 llama-edge 优先
    let (e, s) = reg.try_acquire(Duration::from_secs(10), "llama3").unwrap();
    let id = {
        let inner = reg.inner.read().unwrap();
        inner
            .iter()
            .find(|(_, v)| v.stable_id == e.stable_id)
            .map(|(k, _)| k.agent_id.clone())
            .unwrap()
    };
    assert_eq!(id, "llama-edge", "exact model match must win over wildcard");
    drop(s);

    // 精确 edge 容量打满后，请求回落到通配 edge
    let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    assert_ne!(
        e1.stable_id, e2.stable_id,
        "second qwen2.5 request should fall back to wildcard edge"
    );
    drop(s1);
    drop(s2);
}

#[tokio::test]
async fn try_acquire_returns_no_model_when_none_match() {
    let reg = Registry::default();
    // 无通配 agent：所有健康 agent 都无法服务 mistral-7b
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    reg.register(
        "qwen-edge".into(),
        IP,
        vec!["qwen2.5".into()],
        4,
        c1.clone(),
    );
    reg.register(
        "llama-edge".into(),
        IP,
        vec!["llama3".into()],
        4,
        c2.clone(),
    );
    assert!(matches!(
        reg.try_acquire(Duration::from_secs(10), "mistral-7b"),
        Err(AcquireError::NoModel)
    ));
}

#[tokio::test]
async fn healthy_models_aggregates_and_excludes_wildcard() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    reg.register(
        "edge-a".into(),
        IP,
        vec!["qwen2.5".into(), "llama3".into()],
        4,
        c1.clone(),
    );
    reg.register(
        "edge-b".into(),
        IP,
        vec!["llama3".into(), "*".into()],
        4,
        c2.clone(),
    );
    // 去重、排序、排除 "*"
    assert_eq!(
        reg.healthy_models(Duration::from_secs(10)),
        vec!["llama3", "qwen2.5"]
    );
    // 失联 agent 的模型不聚合
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(reg.healthy_models(Duration::from_millis(10)).is_empty());
}
