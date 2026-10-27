//! 网关领域错误：库层用类型化错误（可 match/分类），anyhow 只留在二进制入口。

use std::io;

/// 网关统一错误。
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("config error: {0}")]
    Config(String),

    #[error("TLS/证书错误: {0}")]
    Tls(#[from] rustls::Error),

    #[error("IO 错误: {0}")]
    Io(#[from] io::Error),

    #[error("SQLite 错误: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("未知错误: {0}")]
    Other(String),

    #[error("证书校验器构造失败: {0}")]
    Verifier(#[from] rustls::client::VerifierBuilderError),

    /// s2n-quic 端点启动失败（`Server::builder().start()`）。
    #[error("QUIC 端点启动失败: {0}")]
    QuicStart(#[from] s2n_quic::provider::StartError),

    /// `listen.rs` 用 `?` 转换 s2n-quic 的 `Infallible`（该类型不可构造，因此分支不会发生）。
    #[error("不可达（Infallible 不可构造）")]
    Infallible(#[from] std::convert::Infallible),
}

impl From<String> for GatewayError {
    fn from(s: String) -> Self {
        GatewayError::Other(s)
    }
}

impl From<&str> for GatewayError {
    fn from(s: &str) -> Self {
        GatewayError::Other(s.to_string())
    }
}
