//! e2e 的裸 QUIC agent（不读请求流/会真正服务请求两种）。

use super::*;

/// 从**指定的本地地址**注册一个裸 agent（不读请求流），返回它的稳定注册结果。
///
/// 存在的理由：`(agent_id, peer_ip)` 是节点身份，而"从**另一个来源 IP** 接入"这件事在
/// e2e 里只有一种造法——**绑不同的本地地址**。macOS 上 `127.0.0.2` 不可用（没有 lo0 别名，
/// 实测 `bind` 报 `Errno 49`），所以用 IPv6 回环：客户端绑 `[::1]:0` 连到 `[::1]:端口`，
/// 服务端看到的对端就是 `::1`，与 `127.0.0.1` 是**真正不同**的两个 IP。
///
/// 前提：网关的 QUIC 监听必须是**双栈**的（绑 `[::]:0`，macOS 的 UDP socket 默认
/// `IPV6_V6ONLY=0`，所以同一个 socket 同时收 v4 与 v6）——实测过两种客户端都能握手成功。
pub async fn register_raw_agent_from(
    gateway_port: u16,
    local: &str,
    certs: &TestCerts,
    agent_id: &str,
    max_concurrency: u32,
) {
    // 目的地按**客户端自己的地址族**取回环地址：双栈监听在**同一个端口**上同时收 v4 与 v6，
    // 而"未指定地址"（`[::]` / `0.0.0.0`）本身不能当目的地。用客户端的地址族推导，
    // 比让调用方各自拼一个地址更不容易写错（第一版就是把 v4 客户端指向了 `[::1]`，握手直接超时）。
    let target = if local.starts_with('[') {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), gateway_port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gateway_port)
    };
    let client_config = agent::tls::rustls_client_tls(
        &certs.ca,
        certs.client_cert.clone(),
        certs.client_key.clone_key(),
    )
    .unwrap();
    let mut conn = test_support::tunnel::connect(target, "localhost", client_config, local)
        .await
        .unwrap();
    let stream = conn.open_bidirectional_stream().await.unwrap();
    let (mut recv, mut send) = stream.split();
    write_frame(
        &mut send,
        &Frame::Register {
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), FrameReader::new(&mut recv).next()).await;
    // 连接搬进永不结束的任务：保持它活着（否则 drop 会摘掉刚注册的条目）
    tokio::spawn(async move {
        let _conn = conn;
        std::future::pending::<()>().await;
    });
}

/// 起一个**会真正服务请求**的 agent 连接（注册 + 持续 accept 代理流）。
///
/// 与 [`spawn_raw_agent`] 的区别：那个故意不读请求流（用来测写背压/可路由性），而
/// "接管不打断在途请求"必须有一个**会把请求跑完**的新连接，否则响应永远不回来，测不出
/// "旧连接被 drain 而不是被掐断"。
///
/// 复用 `agent::stream::handle_stream`（真实 agent 用的同一条转发实现），所以这里测的是
/// 端到端的真实路径，不是自造的简化版。
pub async fn spawn_serving_agent(
    gw: &Gateway,
    certs: &TestCerts,
    agent_id: &str,
    upstream: SocketAddr,
    max_concurrency: u32,
) -> tokio::task::JoinHandle<()> {
    let client_config = agent::tls::rustls_client_tls(
        &certs.ca,
        certs.client_cert.clone(),
        certs.client_key.clone_key(),
    )
    .unwrap();
    let conn = test_support::tunnel::connect(gw.quic_addr, "localhost", client_config, "0.0.0.0:0")
        .await
        .unwrap();
    // 先拆（与真实 agent 同一形状，见 `agent/src/lib.rs`）：Handle 用来开流发 Register，
    // acceptor 用来收网关推进来的代理请求流——acceptor 是单消费者，只能拿一次。
    let (mut handle, mut acceptor) = conn.split();

    // 注册（与真实 agent 同一条路径：开一条双向流、写一帧 Register）
    let stream = handle.open_bidirectional_stream().await.unwrap();
    let (mut reg_recv, mut reg_send) = stream.split();
    write_frame(
        &mut reg_send,
        &Frame::Register {
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    reg_send.finish().unwrap();
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        FrameReader::new(&mut reg_recv).next(),
    )
    .await;

    // 之后持续服务代理流，直到连接被网关关掉（accept 返回错误/None）
    // e2e-bare-client: 这条 client 只用来把上游的响应**转发完**（mock-llm 的正文停顿是 3s），
    // 它的存活时间由被测的连接与 mock 决定，不是"一个本该有界的步骤"；加超时反而会让
    // "旧连接被 drain 期间请求仍在跑"这件事变成超时驱动的假象。
    let http = reqwest::Client::new();
    let upstream = format!("http://{upstream}");
    tokio::spawn(async move {
        while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
            let http = http.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let _ = agent::stream::handle_stream(stream, http, upstream, false).await;
            });
        }
    })
}

/// 起一个**裸 QUIC agent**：注册成功后什么都不做——**不读请求流、不回帧、也不发心跳**。
///
/// 连接被移进一个永不结束的 keep-alive 任务：既保证它活到测试结束，也保证没有任何代码
/// 会去 accept/read 请求流。两个用途：
/// - 写背压：请求帧撑爆对端流控窗口 → `tunnel_write` 超时（见 `write_backpressure`）；
/// - 可路由性：注册后从不心跳 → `last_seen` 过期，`agent_count()` 仍计入它、
///   `healthy_agent_count()` 不计（见 `lifecycle`）。
pub async fn spawn_raw_agent(
    gw: &Gateway,
    certs: &TestCerts,
    agent_id: &str,
    max_concurrency: u32,
) {
    let client_config = agent::tls::rustls_client_tls(
        &certs.ca,
        certs.client_cert.clone(),
        certs.client_key.clone_key(),
    )
    .unwrap();
    let mut conn =
        test_support::tunnel::connect(gw.quic_addr, "localhost", client_config, "0.0.0.0:0")
            .await
            .unwrap();
    let stream = conn.open_bidirectional_stream().await.unwrap();
    let (mut reg_recv, mut reg_send) = stream.split();
    write_frame(
        &mut reg_send,
        &Frame::Register {
            agent_id: agent_id.into(),
            models: vec!["mock-llm".into()],
            max_concurrency,
            version: "test".into(),
        },
    )
    .await
    .unwrap();
    reg_send.finish().unwrap();
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        FrameReader::new(&mut reg_recv).next(),
    )
    .await;
    wait_for_agents(gw, 1, Duration::from_secs(5)).await;

    tokio::spawn(async move {
        let _keep_alive = (conn, reg_recv);
        std::future::pending::<()>().await;
    });
}
