//! agent 测试：监听任务的生命周期（方法非法/转发失败/半关后的清理）。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（P3-2）：**方法非法这条 `Err` 路径不能把监听任务留在那儿**。
///
/// 修复前，方法守卫排在 `tokio::spawn` 监听任务**之后**，而 `listener.abort()` 只在成功
/// 路径的末尾调用 ⇒ 这条 `return` 泄漏一个仍持有读半边的任务：它继续消费网关发来的帧
/// （于是下面这个探测里"网关再写帧"一直成功）。修复后读半边随作用域一起丢弃，QUIC 会回过
/// STOP_SENDING，网关这边的写就会失败。
#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_method_leaves_no_listener_holding_the_stream() {
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
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 12,
            method: "BAD METHOD".into(), // 含空格 ⇒ Method::from_bytes 必失败
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
    let err = handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("非法方法必须是 Err");
    assert!(format!("{err:#}").contains("request_id=12"));

    // 先读掉那条 400（行为本身由上一个用例钉住），reader **留着不 drop**：免得"网关这半边
    // 关掉读方向"变成干扰项。
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    assert!(matches!(frame, Frame::Error { code: 400, .. }), "{frame:?}");

    // 关键探测：故意挑一个**监听者会忽略**的帧型（Cancel/EOF 会让泄漏的监听任务自己退出，
    // 那就测不出泄漏了）。修复前写会一直成功（对端还有人在收），修复后应当变成 Err。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut stopped = false;
    while tokio::time::Instant::now() < deadline {
        let probe = write_frame(
            &mut gw_send,
            &Frame::Heartbeat {
                agent_id: "probe".into(),
                inflight: 0,
            },
        )
        .await;
        if probe.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stopped,
        "非法方法返回后，agent 不该还留着持有读半边的监听任务（对端仍在收帧）"
    );
    drop(gw_send);
}

/// 规格（P3-2 的另一半）：**监听任务被 spawn 之后**的任何返回路径（这里是"上游连不上"，
/// 方法合法 ⇒ 走的是正常 spawn 分支）也必须把监听任务收掉。
///
/// 这条是 `AbortOnDrop` 守卫的**使用点**证明：把守卫换成裸 `tokio::spawn` 而保留"方法守卫
/// 上移"，只有这条会红（前一条探针测不到，因为那条路径压根不再 spawn）。
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_forward_leaves_no_listener_holding_the_stream() {
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
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 13,
            method: "POST".into(), // 合法 ⇒ 会走到 spawn 监听任务那一步
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
    // 上游指向没人监听的端口 ⇒ forward 失败 ⇒ 返回 502 那条 Err
    handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("上游连不上必须是 Err");

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    assert!(matches!(frame, Frame::Error { code: 502, .. }), "{frame:?}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut stopped = false;
    while tokio::time::Instant::now() < deadline {
        if write_frame(
            &mut gw_send,
            &Frame::Heartbeat {
                agent_id: "probe".into(),
                inflight: 0,
            },
        )
        .await
        .is_err()
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stopped,
        "转发失败返回后，agent 不该还留着持有读半边的监听任务（对端仍在收帧）"
    );
    drop(gw_send);
}

/// 规格（P3-3）：**"网关提前半关请求流"必须是可观测的**。
///
/// 取消的契约是"网关显式发 `Frame::Cancel`"；而 agent 的监听任务把请求方向的**干净 EOF**
/// 也当成取消（兜底）。今天网关每条放弃在途请求的路径都先发 Cancel 再 `finish()`，所以 EOF
/// 兜底只在"响应还没开始"时被触发就意味着**契约被破坏**——这条测试就钉住"那一刻要留下 warn"。
///
/// 用 `current_thread` runtime：日志捕获依赖 `set_default` 的线程局部性（见 `CapturedLogs`）。
#[tokio::test(flavor = "current_thread")]
async fn a_gateway_half_close_before_the_response_leaves_a_warning() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"接了不答"的上游：agent 会停在等响应头上，于是下面的半关一定发生在响应之前。
    let hang = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑本地端口");
    let hang_addr = hang.local_addr().expect("取端口");
    tokio::spawn(async move {
        if let Ok((conn, _)) = hang.accept().await {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        }
    });

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
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 14,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");
    // **故意不发 Cancel 就半关写半边** —— 契约违背现场。
    let _ = gw_recv;
    tokio::io::AsyncWriteExt::shutdown(&mut gw_send)
        .await
        .expect("半关应当成功");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    // 让 handle_stream 去等那个不答的上游；监听任务同时看到 FIN。
    let handle = tokio::spawn(async move {
        handle_stream(
            agent_stream,
            upstream_client().unwrap(),
            format!("http://{hang_addr}"),
            false,
        )
        .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut text = String::new();
    while tokio::time::Instant::now() < deadline {
        text = logs.text();
        if text.contains("before the response") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        text.contains("before the response"),
        "网关在响应之前半关请求流 = 契约违背，必须留下 warn；捕获到的日志：\n{text}"
    );

    handle.abort();
}

/// 规格（P3-3 的对照）：**响应已经开始之后对端半关 = 合法收尾，不该报契约违背。**
///
/// 与上一条互为对照：上一条钉"响应前 EOF ⇒ warn"，这条钉"响应后 EOF ⇒ 不 warn"；
/// 只满足一条的实现都是错的（永远 warn = 噪声，永远不 warn = 漏掉契约违背）。
/// 关键在时序：FIN 必须在**监听任务还活着**的时候到达（响应头已写出、响应体还在流），
/// 否则测试会因为"监听任务已被 AbortOnDrop 收掉"而假绿。
#[tokio::test(flavor = "current_thread")]
async fn a_gateway_half_close_after_the_response_is_not_a_warning() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"只回响应头、不结束响应体"的上游：agent 会停在流式回传阶段。
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑本地端口");
    let up_addr = upstream.local_addr().expect("取端口");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if let Ok((mut conn, _)) = upstream.accept().await {
            let mut buf = [0u8; 2048];
            let _ = conn.read(&mut buf).await;
            // 没有 content-length ⇒ 流式；**先只发头**，连接保持打开
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

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
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 15,
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
    let handle = tokio::spawn(async move {
        handle_stream(
            agent_stream,
            upstream_client().unwrap(),
            format!("http://{up_addr}"),
            false,
        )
        .await
    });

    // 等 agent 把响应头写出来（= `response_started` 已置位），再半关。
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等响应头超时")
        .expect("读帧失败")
        .expect("应当有一条帧");
    assert!(
        matches!(frame, Frame::ProxyResponseHead { .. }),
        "先到的应当是响应头：{frame:?}"
    );

    tokio::io::AsyncWriteExt::shutdown(&mut gw_send)
        .await
        .expect("半关应当成功");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let text = logs.text();
    assert!(
        !text.contains("before the response"),
        "响应之后的半关是合法收尾，不该报契约违背；捕获到的日志：\n{text}"
    );

    handle.abort();
}
