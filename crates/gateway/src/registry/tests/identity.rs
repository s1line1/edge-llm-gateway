//! registry 测试：节点身份 `(agent_id, peer_ip)` 与来源 IP 归一/告警。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（D1，**本特性的主判据**）：身份是 `(agent_id, peer_ip)`——同名**不同来源**是
/// **两个并存的节点**，同名**同来源**才是接管。
///
/// 为什么这条是主判据：真实双源（两个不同的 socket 源地址）在 e2e 里要双栈监听才造得出来
/// （见 `specs/agent-node-identity/research.md` R3 的实测），而"注册表按不按组合键区分"是
/// 纯逻辑——在这里直接喂两个 `IpAddr` 就能钉死，且能变异验证。
///
/// 变异验证：把 `AgentKey` 的 `peer_ip` 从 `Hash`/`Eq` 里去掉（或固定成常量）⇒ 本用例红
/// （第二条注册会顶掉第一条，`len()` 变成 1）。
#[tokio::test]
async fn same_id_from_two_ips_is_two_nodes_and_same_ip_takes_over() {
    let reg = Registry::default();

    // ① 同名、两个不同来源：两条并存
    let mut first = Registration::new(&reg);
    let a1 = reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    first.note("edge".into(), IP, a1);
    let mut second = Registration::new(&reg);
    let a2 = reg.register(
        "edge".into(),
        OTHER_IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    second.note("edge".into(), OTHER_IP, a2);
    assert_eq!(reg.len(), 2, "同名不同来源必须是两个并存的节点");
    assert_ne!(a1, a2, "两条连接各有自己的 stable_id");

    // ② 心跳只刷新**自己那一条**：给 first 发心跳，second 的新鲜度不受影响
    let before = reg
        .snapshot(Duration::from_secs(10))
        .into_iter()
        .find(|i| i.agent_id == "edge")
        .map(|i| i.last_seen_secs_ago);
    assert!(before.is_some());
    assert!(
        reg.heartbeat_if_same("edge", IP, a1),
        "first 的心跳必须落在自己那条上"
    );
    assert!(
        !reg.heartbeat_if_same("edge", IP, a2),
        "用 first 的来源 IP 去刷 second 的 stable_id 必须失败（键对不上）"
    );
    assert!(
        reg.heartbeat_if_same("edge", OTHER_IP, a2),
        "second 的心跳也必须落在自己那条上"
    );

    // ③ 摘除互相独立：first 断开只摘掉 first 那条
    drop(first);
    assert_eq!(reg.len(), 1, "只摘掉本连接那一条，另一条不受影响");
    assert!(
        reg.heartbeat_if_same("edge", OTHER_IP, a2),
        "second 仍然活着"
    );
    drop(second);
    assert_eq!(reg.len(), 0);

    // ④ 同名**同来源** = 接管：表里仍只有一条，且属于后注册的那条连接
    let mut third = Registration::new(&reg);
    let b1 = reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    third.note("edge".into(), IP, b1);
    let mut fourth = Registration::new(&reg);
    let b2 = reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    fourth.note("edge".into(), IP, b2);
    assert_eq!(reg.len(), 1, "同一个 (id, ip) 只能有一条：接管而不是追加");
    assert_eq!(
        reg.inner
            .read()
            .unwrap()
            .get(&AgentKey::new("edge", IP))
            .map(|e| e.stable_id),
        Some(b2),
        "条目应属于后注册的那条连接"
    );
    // 旧连接退出不得误摘新条目（stable_id 对不上）
    drop(third);
    assert_eq!(reg.len(), 1);
    drop(fourth);
    assert_eq!(reg.len(), 0);
}

/// 规格（D2 + C2 定案）：同一个 `agent_id` 从**新的来源 IP** 接入时打一条 `warn`，带上
/// 新 IP 与该 id 已知的其他 IP；同名**同来源**重连（接管）**不许**打 warn（那是正常事件，
/// 每次 agent 重连都会发生，打 warn 就成了噪声）；全新节点也不打 warn（首注册由调用方的
/// "agent registered" 那条 info 负责）。
///
/// 变异验证：把 warn 的条件改成"只要该 id 出现过"⇒ 第二条断言红（接管也会 warn）；
/// 改成不打日志 ⇒ 第一条红。
#[tokio::test(flavor = "current_thread")]
async fn ip_change_warns_once_but_takeover_and_first_registration_stay_quiet() {
    let (_guard, logs) = capture_logs();

    // ① 全新节点：只 debug，不 warn
    let reg = Registry::default();
    reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );
    let text = captured_text(&logs);
    assert!(
        !text.contains("additional source IP"),
        "首注册不该报 IP 变动：{text}"
    );
    assert!(text.contains("first registration for this node"));

    // ② 同名同来源重连 = 接管：debug，不 warn
    reg.register(
        "edge".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );
    let text = captured_text(&logs);
    assert!(
        !has_warn(&logs),
        "同名同源接管**一条 warn 都不该有**（那是每次重连都会发生的正常事件）：{text}"
    );
    assert!(text.contains("taking over the entry"));

    // ③ 同名**不同来源** = 新的来源 IP：warn 一条，带 new_ip 与 other_ips
    reg.register(
        "edge".into(),
        OTHER_IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );
    let text = captured_text(&logs);
    assert!(
        text.contains("additional source IP"),
        "同名新来源必须打 warn（D2 要的那个信号）：{text}"
    );
    assert!(
        text.contains("new_ip=127.0.0.2") && text.contains("127.0.0.1"),
        "warn 必须同时带上新 IP 与已知的其他 IP：{text}"
    );
    // 两个节点都在表里（D1：不拒绝、并存）
    assert_eq!(reg.len(), 2);
}

/// 规格（R4）：IP 归一——剥端口、v4-mapped IPv6 折叠成 IPv4、其余 IPv6 原样。
///
/// 变异验证：去掉 v4-mapped 那一支 ⇒ 第 ② 条断言红；不剥端口 ⇒ 第 ① 条断言红
/// （同一台机器换源端口会被当成新节点，接管永不触发）。
#[test]
fn peer_ip_is_normalised_port_stripped_and_v4_mapped_folded() {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    // ① 剥端口：同 IP 不同端口 → 同一个键
    let a = super::keys::normalize_socket_addr(SocketAddr::from((
        Ipv4Addr::new(203, 0, 113, 7),
        51234,
    )));
    let b = super::keys::normalize_socket_addr(SocketAddr::from((
        Ipv4Addr::new(203, 0, 113, 7),
        60000,
    )));
    assert_eq!(a, b, "端口不参与身份：换源端口必须仍是同一个节点");
    assert_eq!(a, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));

    // ② v4-mapped IPv6 → IPv4（双栈 socket 对 v4 对端就是这么报的）
    let mapped = super::keys::normalize_socket_addr(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0207)),
        51234,
    ));
    assert_eq!(
        mapped,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        "v4-mapped 必须折叠成 IPv4，否则同一台机器在双栈下会被当成两个节点"
    );

    // ③ 其余 IPv6 原样保留
    let v6 = super::keys::normalize_socket_addr(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        51234,
    ));
    assert_eq!(
        v6,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
}
