//! agent 测试：心跳/注册/断线重连：一条连接的存活判据。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 回归测试：**单次心跳超时不得立刻拆掉连接**。
///
/// 旧实现把心跳等待硬编码成 5s（等于默认心跳间隔），一次超时就返回 Err → `run()`
/// 视为致命 → 主动断开 → 重连又撞握手限时，实测在高并发下形成风暴，期间网关没有
/// 任何健康 agent（所有请求 503）。
///
/// 服务器只把**第一次**心跳的回包拖长（> 等待上限），之后一律立刻回包；于是
/// "成功会重置失败计数"这一点与测试里掐的时刻无关：第一次必超时、其后必成功。
/// 若容忍逻辑被改回"一次失败即退出"，循环会在第一次超时后结束，断言立刻失败。
#[tokio::test]
async fn a_single_heartbeat_timeout_does_not_immediately_tear_down_the_connection() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let addr = test_server_that_delays_heartbeat_reply(
        &ca,
        srv_cert,
        srv_key,
        // 远大于等待上限（interval 40ms × 3 = 120ms），保证第一次心跳必然超时；
        // 注意服务器每条流独立处理，所以这次延迟只影响第一次心跳。
        Duration::from_millis(200),
    )
    .await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();

    let mut handle = connect_for_test(&cfg, cc).await;
    let task = tokio::spawn(heartbeat_loop(
        handle.clone(),
        "agent-z".into(),
        Duration::from_millis(40),
    ));

    // 第一次心跳在 ≈160ms 超时；其后每次心跳都在 40ms 内立刻回包并重置计数。
    // 跨到 1.2s：若"单次失败就退出"的旧行为回来了，任务早已结束。
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !task.is_finished(),
        "单次心跳超时就拆了连接：应当容忍失败，把「连接是否真死」交给网关 stale 判定"
    );
    assert!(
        handle.open_bidirectional_stream().await.is_ok(),
        "连接应当仍然可用"
    );
    task.abort();
}

#[tokio::test]
async fn dead_heartbeat_forces_a_reconnect() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut rx) = test_server_that_only_serves_register(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));

    // 第一条连接：注册流被服务端读掉并 finish，所以注册能正常完成
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("agent should connect")
        .expect("first connection");

    // 之后的心跳流会被服务端 reset → 心跳任务结束。这条连接此时在网关眼里已经死了
    // （心跳是网关判定存活状态的唯一依据），所以 agent 必须主动断开重连 ——
    // 而不是抱着一条"看起来还开着"的连接静默等下去（那种状态下网关会把所有请求判 503，
    // 两侧都没有日志，只能人工重启）。没有这个断言，这条静默路径可以再次溜回去。
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a dead heartbeat must force a reconnect, not a silent zombie")
        .expect("second connection");

    task.abort();
}

#[tokio::test]
async fn heartbeat_loop_breaks_when_connection_closed() {
    let handle = test_connection().await;
    // 关闭连接：之后 open_bidirectional_stream 必然失败 → 心跳循环返回 Err
    handle.close(0u32.into());
    let result = heartbeat_loop(handle, "agent-x".into(), Duration::from_millis(10)).await;
    assert!(
        result.is_err(),
        "heartbeat should fail after connection closed"
    );
}

#[tokio::test]
async fn heartbeat_loop_sends_frames_on_live_connection() {
    let mut handle = test_connection().await;
    // 间隔 20ms、运行 120ms：心跳任务会反复开流（写帧 + 等 EOF）
    let task = tokio::spawn(heartbeat_loop(
        handle.clone(),
        "agent-y".into(),
        Duration::from_millis(20),
    ));
    tokio::time::sleep(Duration::from_millis(120)).await;
    // 连接仍存活（未被心跳逻辑破坏）
    assert!(handle.open_bidirectional_stream().await.is_ok());
    task.abort();
}

#[tokio::test]
async fn run_loop_retries_when_connect_fails() {
    let (ca, _srv_cert, _srv_key, cli_cert, cli_key) = gen_pki();
    let cfg = test_agent_config(
        SocketAddr::from(([127, 0, 0, 1], 1)), // 必然连接失败
        ca,
        cli_cert,
        cli_key,
    );
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));
    // 第一次连接失败 → Err 分支 → 退避重试（覆盖 71/73-74 行）
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(!task.is_finished(), "run loop should keep retrying");
    task.abort();
}

#[tokio::test]
async fn run_loop_handles_clean_disconnect() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut rx) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));
    // 等 agent 连上
    let server_handle = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("agent should connect")
        .unwrap();
    // 服务端主动关闭连接 → agent 干净断开（Ok 分支）→ 退避重连
    server_handle.close(0u32.into());
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !task.is_finished(),
        "run loop should keep running after disconnect"
    );
    task.abort();
}
