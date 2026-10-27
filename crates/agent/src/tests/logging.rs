//! agent 测试：访问日志与 accept 循环的可观测性。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（P2-2 的第二轮缺口）：**accept 循环那行 `warn!("proxy stream failed")` 必须真的打出来**。
///
/// 既有两条（502 / 非法方法）都是**直接调 `handle_stream`**，于是只证明了"错误链带得上上下文"，
/// 而"调用方确实把它打了出来"这一步靠读码（`lib.rs` 里那行 warn）。这条走**真 accept 循环**：
/// 真跑 `run()`，让 `connect_once` 自己 accept 网关开的流、自己处理它的 Err。
///
/// 判据三层：客户端仍拿到 400（行为不变）→ 日志里有 `proxy stream failed` → 那行里带着
/// `request_id=21` 与路径（"哪个请求失败了"必须能从日志里读出来，这是 P2-2 的全部意义）。
#[tokio::test(flavor = "current_thread")]
async fn the_accept_loop_reports_a_failed_proxy_stream_with_its_context() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) =
        test_server_that_serves_register_and_returns_the_connection(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let agent = tokio::spawn(run(cfg, cc));

    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");
    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    // 含空格的方法名 ⇒ `Method::from_bytes` 必失败 ⇒ `handle_stream` 走 Err 分支（确定性，不碰上游）
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 21,
            method: "BAD METHOD".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    // 行为不变：客户端拿到的仍是 400
    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match reply {
        Frame::Error { code, .. } => assert_eq!(code, 400, "非法方法仍是客户端问题"),
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }

    // 关键断言：那行 warn 真的出现了，而且带得上"哪个请求、哪条路径"
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut text = String::new();
    while tokio::time::Instant::now() < deadline {
        text = logs.text();
        if text.contains("proxy stream failed") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        text.contains("proxy stream failed"),
        "accept 循环必须报告这条失败（P2-2 修的就是它以前被 `let _ =` 吞掉）：\n{text}"
    );
    assert!(
        text.contains("request_id=21") && text.contains("/v1/chat/completions"),
        "那行 warn 必须能说清是哪个请求、哪条路径：\n{text}"
    );

    agent.abort();
}

/// 跑完一次**成功**的代理请求（假网关 → agent → 假上游），返回时 agent 侧已经写完 done。
async fn run_one_proxied_request(request_log: bool) {
    let (upstream, _max_inflight, _served) = counting_upstream(Duration::from_millis(1)).await;
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (_gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 21,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        upstream,
        request_log,
    )
    .await
    .expect("这次请求应当成功（假上游会正常回 200）");
    // `gw_recv`/`gw_send` 在这里 drop：请求已经跑完，不需要再读响应帧
}

/// 规格（记录 P2-2 的另一半）：**`request_log`（默认 true）不是空操作**——成功路径要按文档
/// 承诺打出 `received` / `responded` / `done`；关掉之后这三条一条都不许有。
///
/// 用 `current_thread` runtime：捕获依赖 `set_default` 的线程局部性（见 `CapturedLogs`）。
#[tokio::test(flavor = "current_thread")]
async fn request_log_controls_the_success_path_info_lines() {
    for (enabled, want) in [(true, true), (false, false)] {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        run_one_proxied_request(enabled).await;
        let text = logs.text();
        for line in [
            "proxy request received",
            "upstream responded",
            "proxy request done",
        ] {
            assert_eq!(
                text.contains(line),
                want,
                "request_log={enabled} 时 `{line}` 该不该出现不符；捕获到的日志：\n{text}"
            );
        }
    }
}
