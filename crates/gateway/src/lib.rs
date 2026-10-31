//! cloud-gateway：公网 OpenAI 兼容入口（可选 HTTPS）+ QUIC 隧道服务端。
//!
//! 本文件只做模块声明与再导出，不放实现：`Gateway` 及其配置在 [`gateway`]，
//! TLS 材料与 rustls 配置构造在 [`tls`]。

pub mod access;
pub mod admin;
mod admin_auth;
mod admin_users;
pub mod auth;
pub mod body;
pub mod config;
pub mod error;
mod evict_close;
pub mod gateway;
pub mod http;
pub mod io_stall;
mod listen;
pub mod login_limiter;
pub mod metrics;
pub mod nofile;
pub mod openai;
pub mod options;
pub mod pki;
pub mod proxy;
pub mod quic;
pub mod ratelimit;
pub mod rbac;
pub mod registry;
mod request_id;
mod shutdown;
pub mod state;
pub mod storage;
mod sync;
mod task_scope;
mod tenant;
mod tenant_limits;
mod tls;
pub mod tunnel;
pub mod ui;
pub mod usage_flush;
pub mod usage_meter;

// 再导出：保住 `gateway::{Gateway, GatewayConfig, TlsPem}` 这些既有导入路径
// （src/config.rs、main.rs 与 tests/e2e/* 都按这些路径引用）。
pub use gateway::{Gateway, GatewayConfig, GatewayIdentity, Options, TunnelTls};
pub use tls::TlsPem;
