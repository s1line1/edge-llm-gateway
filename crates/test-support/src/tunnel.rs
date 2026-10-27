//! 裸 QUIC client：测试里"以证书身份连上网关"的那段 builder 样板。
//!
//! 调用方仍然自己构造 `rustls::ClientConfig`（gateway 测试用 `agent::tls::rustls_client_tls`，
//! agent 测试用本 crate 的 `crate::tls::rustls_client_tls`），这里只负责 s2n-quic 端点与
//! 连接。**不要**把 TLS 配置也复制进来：ALPN/mTLS 的单一实现必须在 `agent::tls`。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use s2n_quic::client::Connect;

/// 用给定的客户端 TLS 配置连接到 `addr`。
///
/// `bind` 是本地监听地址（`"0.0.0.0:0"` 或 `"[::1]:0"`）；`server_name` 必须与服务端
/// 证书 SAN 匹配。失败带上下文（`anyhow::Context`），测试失败时能直接看出是 TLS、
/// bind 还是 connect 那一步。
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    client_config: rustls::ClientConfig,
    bind: &str,
) -> anyhow::Result<s2n_quic::Connection> {
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            client_config,
        )))
        .context("configure test QUIC TLS")?
        .with_io(bind)
        .context("bind test QUIC client")?
        .start()
        .context("start test QUIC client")?;
    client
        .connect(Connect::new(addr).with_server_name(server_name.to_string()))
        .await
        .context("connect test QUIC client")
}
