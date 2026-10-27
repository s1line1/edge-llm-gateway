//! agent 测试：路径守卫：越权路径不得到达上游。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（`PROJECT_SCAN` P1-2 的 agent 侧）：越权路径**不得到达上游**，且客户端拿到 400。
///
/// `stream.rs` 里那几条纯函数测试证明判据对；这条证明它**真接在数据路径上**：假网关往一条
/// 双向流里写记录里的 PoC（`DELETE /v1/../api/delete`），真跑 [`handle_stream`]，断言
/// ① 回包是一条 `code: 400` 的 Error 帧（网关据此让客户端看到 400，而不是无因果的 502），
/// ② 上游那个 listener **一次连接都没有**——这才是漏洞本身（上游通常是 agent 同机的
/// Ollama，`/api/delete` 会直接删模型）。
#[tokio::test]
async fn a_traversal_path_never_reaches_the_upstream_and_returns_400() {
    // 上游：只用来数连接，正常实现里 agent 不该连它
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_url = format!("http://{}", upstream.local_addr().expect("addr"));

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

    // 假网关：开一条双向流，写一个越权的 ProxyRequest
    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 7,
            method: "DELETE".into(),
            path: "/v1/../api/delete".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    // agent 侧：accept 出流（生产里 `run_loop` 就是这么给的）并真跑
    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("应当在 5s 内收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let task = tokio::spawn(handle_stream(
        agent_stream,
        // 与生产同一条构造路径：测试不该复制一份"没加固的客户端"（那正是 P2-4 的形状）
        upstream_client().unwrap(),
        upstream_url,
        false,
    ));

    // ① 回包 = 400 Error 帧
    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("拒绝不该拖延")
        .expect("读帧不该出错")
        .expect("应当有回帧");
    match reply {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(7), "错误帧要能对上请求");
            assert_eq!(code, 400, "网关拿这个 code 当客户端看到的状态码");
            assert!(message.contains("path"), "文案要指出是路径问题：{message}");
        }
        other => panic!("越权路径应当被拒，实际收到 {other:?}"),
    }

    // ② 上游一次都没被连（300ms 内 accept 必须超时）
    assert!(
        tokio::time::timeout(Duration::from_millis(300), upstream.accept())
            .await
            .is_err(),
        "越权路径到达了上游——这正是 P1-2"
    );

    task.await
        .expect("handle_stream 不该 panic")
        .expect("拒绝是正常结束，不该是 Err");
}
