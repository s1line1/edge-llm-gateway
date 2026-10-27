//! 测试专用支持：PKI 生成与裸 QUIC 连接。
//!
//! 这个 crate **只**给 `crates/gateway/tests` 与 `crates/agent/src/tests` 的
//! dev-dependencies 使用，`publish = false`。它不依赖 gateway/agent 类型，避免
//! dev-dependency 环；也因此可以同时服务两端。
//!
//! 目前只收敛两件确有重复的事：证书工厂（原先 5 份）与裸 QUIC client 的
//! builder/TLS/connect 样板（原先 10+ 处）。进程 harness（`sighup.rs` 与
//! `e2e/signals.rs`）暂不并入：两者对"哪个二进制、传什么参数、等哪一行日志"的
//! 语义不同，抽成一个通用 helper 会把差异推到调用点，收益不抵风险。

pub mod pki;
pub mod tunnel;
