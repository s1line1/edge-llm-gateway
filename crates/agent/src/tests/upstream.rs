//! agent 测试：上游 HTTP 客户端的安全策略与错误映射。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（记录 P2-4）：**上游的重定向不许被跟随**。
///
/// 跟随的代价不是"多一跳"：307/308 会把方法与 **prompt 原样重发**到 `Location` 指定的地址
/// （内网服务、`169.254.169.254` 云元数据），并把那边的响应回给调用方。判据有两条，缺一不可：
/// ① 客户端拿到的是上游自己回的 307（而不是被跟随后的 200）；
/// ② "第二个服务器"**一次连接都没有**——这才是"prompt 没被送出去"。
#[tokio::test]
async fn the_upstream_client_does_not_follow_redirects() {
    let (victim, mut victim_rx) =
        one_shot_http("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nexfiltr".to_string()).await;
    let (attacker, _attacker_rx) = one_shot_http(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{victim}/steal\r\nContent-Length: 0\r\n\r\n"
        ))
        .await;

    let client = upstream_client().unwrap();
    let resp = client
        .post(format!("http://{attacker}/v1/chat/completions"))
        .body(r#"{"model":"m","messages":[{"role":"user","content":"TOPSECRET"}]}"#)
        .send()
        .await
        .expect("上游能连上，请求本身必须成功");

    assert_eq!(
        resp.status().as_u16(),
        307,
        "不跟随重定向：把上游自己的 3xx 原样返回，而不是替它去访问 Location"
    );

    // ② 关键判据：prompt 绝不得到达 Location 指向的地址
    if let Ok(Some(request)) =
        tokio::time::timeout(Duration::from_millis(500), victim_rx.recv()).await
    {
        panic!("agent 跟随了重定向：prompt 被送到 {victim}，请求内容：{request}");
    }
}

/// 规格（记录 P2-4 的另一半）：上游客户端**不读环境代理**。
///
/// ⚠️ 今天这条测试**通过的原因**是 `reqwest` 在本仓库关了默认特性、`system-proxy` 未启用
/// （`cargo tree -p reqwest -f "{f}"` 可复核），而不是因为 `.no_proxy()` 真的被验证了——
/// 特性没开时环境代理根本不会被读，观测不到差别。它的价值是**日后**：谁把 `reqwest` 的
/// 默认特性打开、又删掉 `upstream_client()` 里的 `.no_proxy()`，这条测试就会红。
#[tokio::test]
async fn the_upstream_client_ignores_environment_proxies() {
    let (proxy, mut proxy_rx) =
        one_shot_http("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_string()).await;
    let (upstream, _upstream_rx) =
        one_shot_http("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()).await;

    let saved = std::env::var("HTTP_PROXY").ok();
    std::env::set_var("HTTP_PROXY", format!("http://{proxy}"));
    let client = upstream_client().unwrap();
    let sent = client
        .post(format!("http://{upstream}/v1/chat/completions"))
        .body(r#"{"model":"m","messages":[{"role":"user","content":"TOPSECRET"}]}"#)
        .send()
        .await;
    match &saved {
        Some(v) => std::env::set_var("HTTP_PROXY", v),
        None => std::env::remove_var("HTTP_PROXY"),
    }

    let resp = sent.expect("必须直连上游成功（经代理会被拒）");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        proxy_rx.try_recv().is_err(),
        "prompt 不该出现在环境变量指定的代理上"
    );
}

/// 规格（记录 P2-2）：**上游连不上时不许只给客户端一个"上游关了"的通用 502，
/// 也不许 agent 侧一行日志都没有**。
///
/// 判据两层：① 隧道里收到的是一条 `Frame::Error{code: 502}`，且消息**不含内网地址/端口**
/// （细节只进 agent 日志，别把内部拓扑透露给 API 调用方）；② 返回的错误链带上
/// `request_id` 与 `path`——accept 循环那行 `warn!("{e:#}")` 就是靠它说清"哪个请求"。
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_upstream_reports_a_generic_502_and_a_contextual_error() {
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
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 9,
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

    // 上游指向一个必然拒绝连接的端口（本测试不监听它）
    let err = handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("上游连不上必须是 Err —— 以前这个 Err 被 spawn 处直接丢掉");

    // ① 客户端侧看到的是**点名原因但不含内部拓扑**的 502
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match frame {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(9));
            assert_eq!(code, 502, "上游不可达应当是 502");
            assert!(
                message.contains("local upstream"),
                "消息要点名是本地这一跳失败了：{message}"
            );
            assert!(
                !message.contains("127.0.0.1") && !message.contains(":1"),
                "不许把内网地址/端口写进客户端可见的错误里：{message}"
            );
        }
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }

    // ② 错误链带得起上下文（accept 循环打印的就是它）
    let chain = format!("{err:#}");
    assert!(
        chain.contains("request_id=9"),
        "错误链缺 request_id：{chain}"
    );
    assert!(
        chain.contains("/v1/chat/completions"),
        "错误链缺 path：{chain}"
    );
    drop(gw_send);
}

/// 规格（记录 P2-2 的另一条静默路径）：**方法非法的请求回 400，而不是静默变成 502**。
#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_method_is_rejected_with_400_instead_of_vanishing() {
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
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 11,
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

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match frame {
        Frame::Error { code, message, .. } => {
            assert_eq!(code, 400, "非法方法是客户端的问题：{message}");
            assert!(message.contains("method"), "消息要指名道姓：{message}");
        }
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }
    assert!(format!("{err:#}").contains("request_id=11"));
    drop(gw_send);
}
