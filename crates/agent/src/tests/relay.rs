//! agent 测试：代理响应回传（响应头 UTF-8、取消后的收尾）。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（记录 P3-16）：**非 ASCII（中文）响应头值必须原样回传给网关**。
///
/// 修好前 agent 回传上游响应头用的是 `v.to_str()`——它只认可见 ASCII，中文值会被**整条丢掉**
/// （不是变空串，是直接消失），于是客户端永远看不到这个头。判据放在**隧道帧**上：
/// 假网关读回 `ProxyResponseHead`，断言里面就是 `x-echo: 张三`。
#[tokio::test(flavor = "multi_thread")]
async fn a_utf8_response_header_survives_the_relay() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 假上游：不管请求内容，回一个带中文响应头的 200
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let body = b"{}";
            let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Echo: 张三\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
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
        .expect("假网关应当拿到句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 7,
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
    let task = tokio::spawn(handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        upstream_url,
        false,
    ));

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let head = loop {
        match tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .expect("等响应头帧超时")
            .expect("读帧失败")
        {
            Some(Frame::ProxyResponseHead { headers, .. }) => break headers,
            Some(_) => continue,
            None => panic!("流在给出响应头之前就结束了"),
        }
    };
    assert!(
        head.iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-echo") && v == "张三"),
        "中文响应头必须原样回传，实际：{head:?}"
    );

    drop(gw_send);
    task.abort();
}

/// 规格（P2-2 的第二轮缺口）：**`cancelled` 这条 `request_log` 也要真的打出来**。
///
/// 既有那条只覆盖成功路径的 received / responded / done。取消路径的判据有两半，缺一不可：
/// 客户端必须收到 `499 cancelled by client`（而不是通用 502），agent 侧必须留下
/// `proxy request cancelled by client` —— 否则"这个请求为什么没了"在两侧都查不出来。
#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_request_logs_its_own_line_and_answers_499() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"接了不答"的上游：agent 停在等响应头上，取消正好落在**响应之前**那个 select 分支
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
            request_id: 33,
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
    // `request_log = true`：这条测试要看的就是那条 INFO
    let task = tokio::spawn(handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        format!("http://{hang_addr}"),
        true,
    ));

    // 先让请求真的打到上游，再发取消（否则测到的是别的路径）
    tokio::time::sleep(Duration::from_millis(200)).await;
    write_frame(&mut gw_send, &Frame::Cancel { request_id: 33 })
        .await
        .expect("写取消帧");

    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("等取消回帧超时")
        .expect("读帧失败")
        .expect("应当有一条回帧");
    match reply {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(33), "取消回帧要能对上请求");
            assert_eq!(code, 499, "客户端取消不是服务端错误：{message}");
            assert!(
                message.contains("cancelled by client"),
                "文案要说清是客户端取消的：{message}"
            );
        }
        other => panic!("取消应当回 499 的 Frame::Error，实际：{other:?}"),
    }
    task.await
        .expect("handle_stream 不该 panic")
        .expect("取消是正常收尾，不该是 Err");

    let text = logs.text();
    assert!(
        text.contains("proxy request received"),
        "取消之前先要有 received：\n{text}"
    );
    assert!(
        text.contains("proxy request cancelled by client"),
        "取消路径必须留下它自己那条 INFO（P2-2；以前 request_log 是空操作）：\n{text}"
    );
}
