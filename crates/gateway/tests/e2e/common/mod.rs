//! e2e 公共辅助：证书生成、测试栈启动等（被各场景模块共享）。

// 公共导入以 pub use 暴露，子场景模块通过 `use super::common::*` 共享
pub use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

pub use agent::{Agent, AgentConfig};
pub use gateway::{error::GatewayError, Gateway, GatewayConfig, Options, TlsPem, TunnelTls};
pub use proto::{
    io::{write_frame, FrameReader},
    Frame,
};
pub use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
pub use serial_test::serial;

mod client;
pub use client::*;
mod pki;
pub use pki::*;
mod pki_gateway;
pub use pki_gateway::*;
mod waits;
pub use waits::*;
mod stack;
pub use stack::*;
mod raw_agent;
pub use raw_agent::*;
#[cfg(test)]
mod step_guard_tests;
