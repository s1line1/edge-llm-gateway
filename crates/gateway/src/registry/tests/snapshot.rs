//! registry 测试：`/admin/agents` 的读模型（快照顺序与字段）。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 契约（`contracts/admin-agents.md`）：同名不同来源时快照返回**两行**，各自带自己的
/// `ip`，且顺序**稳定**（按 `(agent_id, ip)`）。
///
/// 前端 `key` 与测试断言都依赖这个稳定序；顺序不稳时同名两行会在渲染层来回换位。
#[tokio::test]
async fn snapshot_lists_same_id_different_ip_as_two_stable_rows() {
    let reg = Registry::default();
    // 故意先用"较大"的 IP 注册，验证输出是按 (id, ip) 排过序的，而不是插入序
    reg.register(
        "edge".into(),
        OTHER_IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );

    let snap = reg.snapshot(Duration::from_secs(10));
    assert_eq!(snap.len(), 2, "同名不同来源必须各占一行");
    let rows: Vec<(&str, &str)> = snap
        .iter()
        .map(|i| (i.agent_id.as_str(), i.ip.as_str()))
        .collect();
    assert_eq!(
        rows,
        vec![("edge", "127.0.0.1"), ("edge", "127.0.0.2")],
        "两行同名，按 (agent_id, ip) 稳定升序"
    );
    // 再取一次：顺序必须一致（稳定序而不是"这次恰好这样"）
    let again: Vec<String> = reg
        .snapshot(Duration::from_secs(10))
        .into_iter()
        .map(|i| i.ip)
        .collect();
    assert_eq!(
        again,
        vec!["127.0.0.1".to_string(), "127.0.0.2".to_string()]
    );
}

#[tokio::test]
async fn snapshot_reports_agent_details() {
    let reg = Registry::default();
    let conn = test_connection().await;
    reg.register(
        "home-1".into(),
        IP,
        vec!["qwen2.5".into(), "llama3".into()],
        2,
        conn.clone(),
    );
    let snap = reg.snapshot(Duration::from_secs(10));
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].agent_id, "home-1");
    assert_eq!(
        snap[0].ip, "127.0.0.1",
        "契约：/admin/agents 每行带来源 IP（已归一、不含端口）"
    );
    assert_eq!(
        snap[0].models,
        vec!["qwen2.5".to_string(), "llama3".to_string()]
    );
    assert_eq!(snap[0].max_concurrency, 2);
    assert_eq!(snap[0].inflight, 0);
    assert!(snap[0].last_seen_secs_ago < 1, "freshly registered agent");
    assert!(
        snap[0].healthy,
        "刚注册的 agent 必须在路由窗口内（复扫 G1）"
    );

    // **结论随窗口变**，而不是某个写死的阈值——这正是复扫 G1 的实质：前端原先拿一个
    // 写死的 15s 去比 `last_seen_secs_ago`，完全无视网关配的 `agent_stale_secs`。
    //
    // 为什么不构造"心跳很旧"的条目：`now_millis()` 是**进程相对**时钟（`epoch().elapsed()`），
    // 测试进程刚起来时它约等于 0，把 `last_seen` 往回拨会被 `saturating_sub` 夹到 0、
    // 反而变成"最新"（实测踩过）。要造旧条目只能真的 sleep；而"窗口一收就不健康、一放就健康"
    // 已经把同一条性质钉住了，且不依赖时钟推进。
    assert!(
        !reg.snapshot(Duration::ZERO)[0].healthy,
        "零窗口下没有任何条目算新鲜"
    );
    assert!(
        reg.snapshot(Duration::from_secs(3600))[0].healthy,
        "同一个条目在足够大的窗口里是健康的 ⇒ 判定跟着窗口走，而不是写死的阈值"
    );

    // 按 agent_id 排序、空注册表为空
    let conn2 = test_connection().await;
    reg.register("agent-a".into(), IP, vec![], 4, conn2.clone());
    let snap = reg.snapshot(Duration::from_secs(10));
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0].agent_id, "agent-a");
    assert_eq!(snap[1].agent_id, "home-1");
    assert!(Registry::default()
        .snapshot(Duration::from_secs(10))
        .is_empty());
}
