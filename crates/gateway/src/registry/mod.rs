//! edge-agent 注册表：`agent_id → 连接 + 健康状态 + 并发占位`。
//!
//! **本文件只做组合**：类型与策略按变更理由分在子模块里——
//! `entry`（条目与健康判据）、`routing`（选路规则）、`table`（表的增删查与快照）、
//! `eviction`（失败记账与摘除）、`admission`（并发占位与 `SlotGuard`）、`keys`（节点身份与
//! IP 归一）——它们都是私有模块，公开路径仍是 `crate::registry::*`：下面的 `pub use`
//! 逐个把子模块里的名字提到本模块，调用方一处都不用改。

use std::{
    collections::HashMap,
    sync::{atomic::AtomicUsize, Arc, RwLock},
};

mod admission;
mod entry;
mod eviction;
mod keys;
mod routing;
mod table;

pub use entry::{Entry, HeadSilence};
pub use routing::{AcquireError, Disposition};
pub use table::{AgentInfo, Registration, RegistryStatus};

/// 注册表的键类型（crate 内可见，**不是公开 API**）：对外只经 `/admin/agents` 的 `ip`
/// 字符串暴露来源。`quic.rs` 要用它做心跳查找。
pub(crate) use keys::{normalize_socket_addr, AgentKey};
pub(crate) use table::MAX_REGISTRATIONS_PER_CONNECTION;

/// 连接身份发号器：给每条注册进来的连接发一个**进程内唯一且永不复用**的编号。
///
/// 为什么不用 `Handle::id()`：那是 s2n-quic 的**端点内部**连接序号，源码注释写的是
/// "stable and internally identifies a connection over the whole lifetime of **an endpoint**"，
/// 而生成器是每个端点各自从 0 开始（s2n-quic-transport/src/endpoint/mod.rs:79,323、
/// src/connection/internal_connection_id.rs:26-32）——跨端点必然撞号：注册表的单元测试
/// 里每次新建一对端点，两条连接的 id 都是 0，于是 `remove_if_same` 会误删同名新连接的条目。
/// 注册表要的是"同一进程内、对一条连接稳定、且不复用"的编号（复用同样会导致误删），自己发号最稳。
static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

/// `(agent_id, peer_ip) → Entry` 的注册表，外加准入（`try_acquire*`）与隧道失败的判定/记账。
///
/// **键是"节点身份"而不是"id"**（2026-10-16 D1）：同一个 `agent_id` 从不同来源 IP 注册时是
/// **两个并存的节点**，各自独立路由；只有 `(agent_id, 同一个 IP)` 再次注册才是接管。
///
/// **两条锁纪律**（都是事故换来的，改动这里的任何方法前先看一眼）：
/// - **写锁下只碰 map 与原子量**：不 `spawn`、不调传输句柄。`tokio::spawn` 若在守卫内 panic，
///   守卫会在 unwind 中释放 → 锁**永久中毒**，之后每一次注册/心跳/选路都跟着 panic
///   （见 `Registry::evict` 与 [`Registry::register`] 的写法：动作一律留到锁外）。
/// - **心跳只取读锁**（见 [`Registry::heartbeat_if_same`]）：它只是刷新一个原子毫秒值，
///   不该与正在选路的读路径互斥。
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<HashMap<AgentKey, Entry>>>,
}

pub(crate) use admission::SlotGuard;

#[cfg(test)]
mod tests;
