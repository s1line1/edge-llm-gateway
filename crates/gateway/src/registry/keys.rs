//! agent 节点身份：`(agent_id, peer_ip)` 与 IP 归一。
//!
//! 纯身份策略，不碰注册表的表/锁；`AgentKey` 同时是注册表的键与 `/admin/agents`
//! 展示口径的来源（见各函数的文档）。

use std::net::{IpAddr, SocketAddr};

#[cfg(test)]
use crate::storage::DEFAULT_TENANT_ID;

/// 一个 agent-node 的身份：对端自报的 `agent_id` + **socket 上看到的来源 IP**。
///
/// **为什么键要含 IP**（2026-10-16 决策 D1）：原来键只有 `agent_id`，于是两台机器用同一个
/// `agent_id` 时会互相顶替（后注册的立刻关掉先注册的），而"同一台机器重连"与"另一台机器
/// 冒用同名"在网关看来完全一样。加上来源 IP 之后：**同 `(id, ip)` = 同一节点重连（接管）**，
/// **同 `id` 不同 `ip` = 两个并存的节点**（各自独立路由）。
///
/// **不含端口**：每次重连源端口都会变，把它放进键等于让接管永不触发——注册表只增不减，
/// 正是刚修完的幽灵条目换个入口重现。
/// **IP 已归一**（[`normalize_ip`]）：v4-mapped IPv6 折叠成 IPv4，否则双栈监听下同一台
/// 机器会因为"v4 连接看到 `127.0.0.1`、双栈连接看到 `::ffff:127.0.0.1`"被当成两个节点。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct AgentKey {
    pub(crate) tenant_id: String,
    pub(crate) agent_id: String,
    pub(crate) peer_ip: IpAddr,
}

impl AgentKey {
    /// 测试/旧调用：归入 `default` tenant。
    #[cfg(test)]
    pub(crate) fn new(agent_id: &str, peer_ip: IpAddr) -> Self {
        Self::new_in_tenant(DEFAULT_TENANT_ID, agent_id, peer_ip)
    }

    pub(crate) fn new_in_tenant(tenant_id: &str, agent_id: &str, peer_ip: IpAddr) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            agent_id: agent_id.to_string(),
            peer_ip: normalize_ip(peer_ip),
        }
    }
}

/// 把 socket 看到的对端地址归一成"裸 IP"。
///
/// 两步，各自都有非做不可的理由：
/// 1. **剥端口**：重连必换源端口，带端口 = 接管永不触发（见 [`AgentKey`]）。
/// 2. **v4-mapped IPv6 折叠**：双栈 socket（绑 `::`）对 IPv4 对端报的是
///    `::ffff:a.b.c.d`。不折叠时同一台机器在"v4 监听"与"双栈监听"下拿到两个不同的 IP，
///    于是被当成**两个并存节点**（D1 的误判形态，而不是安全退化）。
///
/// 归一**只此一处**：`/admin/agents` 的 `ip` 字符串也走它，避免"键里归一、展示里没归一"
/// 的劈叉。纯函数，好单测。
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// 从 `SocketAddr` 取归一后的 IP（注册与心跳的唯一入口）。
pub(crate) fn normalize_socket_addr(addr: SocketAddr) -> IpAddr {
    normalize_ip(addr.ip())
}
