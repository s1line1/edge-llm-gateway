//! 注册表本身：`agent_id → Entry` 的增删查、快照、并发占位，以及绑定在连接上的摘除守卫。
//!
//! 本模块只回答「谁在表里、它新鲜吗、还有额度吗」；**选路规则**在 [`super::routing`]、
//! **失败记账与摘除**在 [`super::eviction`]——三者的变更理由不同（表几乎不变，路由随模型
//! 匹配需求变，摘除策略随事故证据变）。

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use serde::Serialize;
use tracing::{info, warn};

use super::entry::{is_fresh, now_millis, since_millis, Entry, NEVER};
use super::routing::{pick, AcquireError};
use super::{Registry, SlotGuard, NEXT_CONN_ID};
use crate::sync::{read_or_recover, write_or_recover};

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
    pub(crate) agent_id: String,
    pub(crate) peer_ip: IpAddr,
}

impl AgentKey {
    pub(crate) fn new(agent_id: &str, peer_ip: IpAddr) -> Self {
        Self {
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

/// agent 明细快照（供 /admin/agents 管理接口序列化）。
#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_id: String,
    /// 来源 IP（已归一、**不含端口**，见 [`AgentKey`]）。
    ///
    /// 为什么要有它：`agent_id` 在 D1 之后**不再唯一**——同一个 id 从两个来源 IP 连进来是
    /// 两个并存节点，只有 `ip` 能把它们区分开（`/admin/agents` 与 Dashboard 都靠它）。
    /// JSON 里是字符串（`"203.0.113.7"` / `"::1"`）：仓库没有其它 `IpAddr` 序列化先例，
    /// 而网关是归一化的唯一来源，消费方只需展示、不需要重新解析。
    pub ip: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 当前在途请求数。
    pub inflight: u32,
    /// 距上次心跳的秒数。
    pub last_seen_secs_ago: u64,
    /// **是否参与路由**：与 `try_acquire` 同一个判据（心跳在 `agent_stale_secs` 之内）。
    ///
    /// 为什么把它算在网关侧（复扫 G1）：前端原先自己拿一个**写死的 15s** 去比
    /// `last_seen_secs_ago`，而同一个页面的顶部用的是网关按 `agent_stale_secs` 算出的
    /// `hlmg_agents_healthy` ⇒ `agent_stale_secs` 一旦不是 15，同一页上"在线总数"与表格行状态
    /// 就会自相矛盾。规则只能有一个来源，所以由网关给出结论。
    pub healthy: bool,
}

/// 一条连接**最多**能注册多少个不同的 `agent_id`。
///
/// **为什么必须有上限**（记录 SL-P2-10）：`Register` 帧是**对端自己发的**，而控制流循环对它
/// 的条数没有任何天然限制。一个持 CA 证书的连接（或一个被拿下的 edge 节点）可以连发
/// `a1..aN`，每条都在表里插一条带 `models: Vec<String>`（单帧上限 `MAX_FRAME` = 64 MiB）的
/// 条目；断开时若只摘最后一条，其余就是**永不回收的幽灵条目**（本仓库没有 stale 清扫器：
/// 心跳过期只是不再可路由，条目本身不动），表现为 `hlmg_agents` 虚高、`/admin/agents` 里
/// 多出一批没有对应进程的行，直到重启。
///
/// 4 是**四倍余量**，不是新配置旋钮：正常部署里一条连接只服务一个 agent 进程，重新注册
/// 同名 id（进程重连/配置刷新）走的是**覆盖**、不占新额度。所以 4 只在"一条连接真的在
/// 托管多个 id"时才会被碰到。
pub(crate) const MAX_REGISTRATIONS_PER_CONNECTION: usize = 4;

/// 已注册条目的摘除守卫：连接任务结束时把条目摘掉——**即使任务 panic**。
///
/// 为什么必须用 Drop（评估记录 P2-11）：`quic::handle_conn` 原先在末尾写一句
/// `if let Some((id, sid)) = &agent_id { registry.remove_if_same(id, *sid) }`。panic 展开时
/// 那句不执行，条目就**永久**留在注册表里——而这个仓库**没有 stale 清扫器**（心跳过期只是
/// 不再可路由），于是 `hlmg_agents` 虚高、`/admin/agents` 里出现幽灵条目，直到重启。
///
/// **记的是"本连接注册过的全部 id"**（不是最后一条，记录 SL-P2-10）：一条连接可以注册多个
/// `agent_id`（`quic::handle_conn_inner` 的控制流循环收 `Register` 帧不设限），只记最后一条的话
/// 断开时只摘一条，其余连同 `models` 永久留在表里（`MAX_REGISTRATIONS_PER_CONNECTION` 是
/// 对它的数量约束，不是替代）。
///
/// 用法：`let mut reg = Registration::new(&registry);` … 注册成功后 `reg.note(id, stable_id)`；
/// 守卫随 `handle_conn` 的栈帧一起 drop。空 `Vec`（从没注册成功）时摘除是 no-op。
pub struct Registration<'a> {
    registry: &'a Registry,
    /// `(agent_id, peer_ip, stable_id)`，**按 `(agent_id, peer_ip)` 去重**：同一节点重新注册
    /// = 覆盖（只有最新那个 `stable_id` 才匹配当前条目，旧的本来就已经 no-op）。
    ///
    /// **为什么这里要带 `peer_ip`**：摘除得按**同一个键**去找条目（[`Registry::remove_if_same`]
    /// 按 `(agent_id, peer_ip)` 定位）。同名的两个节点是两条独立条目，只按 `agent_id` 摘会在
    /// 双节点场景里摘错人（或摘不掉）。
    agent: Vec<(String, IpAddr, usize)>,
}

impl<'a> Registration<'a> {
    pub fn new(registry: &'a Registry) -> Self {
        Self {
            registry,
            agent: Vec::new(),
        }
    }

    /// 这条连接**还能不能**再注册一个节点：`(agent_id, peer_ip)` 已在本连接名下
    /// （= 重新注册/刷新）时恒真；否则要求还没用满 [`MAX_REGISTRATIONS_PER_CONNECTION`]。
    ///
    /// **必须在 `Registry::register` 之前问**（调用点顺序见 `quic.rs`）：注册已经插表之后再
    /// 拒绝，那条 `Entry` 就没人负责摘了——正是本守卫要防的幽灵条目。
    pub fn accepts(&self, agent_id: &str, peer_ip: IpAddr) -> bool {
        let ip = normalize_ip(peer_ip);
        self.agent
            .iter()
            .any(|(id, kip, _)| id == agent_id && *kip == ip)
            || self.agent.len() < MAX_REGISTRATIONS_PER_CONNECTION
    }

    /// 记下"这条连接注册成了哪个节点 / stable_id"。
    ///
    /// 同一 `(agent_id, peer_ip)` 重新注册时**覆盖**：只有最后一次的 `stable_id` 才匹配当前
    /// 条目，用旧的 stable_id 摘除是 no-op（`remove_if_same` 会比对）。
    pub fn note(&mut self, agent_id: String, peer_ip: IpAddr, stable_id: usize) {
        let ip = normalize_ip(peer_ip);
        match self
            .agent
            .iter_mut()
            .find(|(id, kip, _)| id == &agent_id && *kip == ip)
        {
            Some(slot) => slot.2 = stable_id,
            None => self.agent.push((agent_id, ip, stable_id)),
        }
    }

    /// 若 `agent_id` 是**本连接**注册的，返回它当前的 `stable_id`；否则 `None`。
    ///
    /// 心跳要靠它把"帧里自报的 id"与"这条连接注册过什么"对上——见
    /// [`Registry::heartbeat_if_same`]。**必须按每个 id 查**（不能只比最后一条）：一条连接可以
    /// 注册多个 id，只认最后一条时，其余 id 的心跳会被当成越权而丢弃（或反过来，让越权的心跳
    /// 替别人的死条目续命）。
    pub fn owned_stable_id(&self, agent_id: &str, peer_ip: IpAddr) -> Option<usize> {
        let ip = normalize_ip(peer_ip);
        self.agent
            .iter()
            .find(|(id, kip, _)| id == agent_id && *kip == ip)
            .map(|(_, _, sid)| *sid)
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        // 逐个摘：判据仍是 `stable_id` 比对，所以**只摘仍属于本连接的那些**——被新连接接管的
        // id 在这里是 no-op，不会误删活条目。
        for (agent_id, peer_ip, stable_id) in &self.agent {
            self.registry.remove_if_same(agent_id, *peer_ip, *stable_id);
        }
    }
}

impl Registry {
    /// 注册 agent；**同一个 `(agent_id, peer_ip)`** 已有连接时，关闭旧连接（接管）。
    ///
    /// 返回本次注册分配的 `stable_id`：调用方之后要用它调 [`Self::remove_if_same`] 摘除条目，
    /// 所以**必须用这个返回值**，不要自己另算一份——`Entry.stable_id` 由这里独占决定，
    /// 两处各算一次就会对不上，连接结束时条目永远摘不掉（注册表只增不减）。
    ///
    /// `peer_ip` 是 **socket 上看到的**对端地址（调用方传 `Handle::remote_addr()` 的 IP），
    /// 不是帧里自报的——自报字段没有可信度。它经 [`normalize_ip`] 归一后参与键。
    pub fn register(
        &self,
        agent_id: String,
        peer_ip: IpAddr,
        models: Vec<String>,
        max_concurrency: u32,
        conn: s2n_quic::connection::Handle,
    ) -> usize {
        self.register_with_grace(
            agent_id,
            peer_ip,
            models,
            max_concurrency,
            conn,
            crate::options::Options::DEFAULT_EVICT_CLOSE_GRACE,
            None,
        )
    }

    /// 同 [`Self::register`]，但显式给出接管旧连接时用的**宽限期**，并可挂一个关闭通知
    /// （通知只给测试用：`s2n-quic` 的连接句柄在关闭后仍能回答 `remote_addr()`，外部观测不到
    /// "关没关"，见 [`crate::evict_close::CloseObserver`]）。
    ///
    /// **为什么接管要宽限**（D3，2026-10-16）：被顶替的那条连接上往往还有在途请求，两类都
    /// 不该被连带打断——已经把请求完整送达上游、模型正在生成的那类，以及还在合法等响应头的
    /// 那类。接管是**正常事件**（agent 重连），不是故障，所以它必须和其它摘除路径走同一套
    /// 处置：先移出路由（新条目入表即是），再等在途收尾或宽限到期才关连接。
    ///
    /// **为什么 `inflight <= 1` 就立刻关**：那个 1 是**本次接管调用自己**占的槽位（调用方先
    /// `try_acquire` 取到旧条目、再重连注册），所以"<=1"等于"没有别人的请求会被牵连"。
    /// 与 [`Registry::evict`] 用同一个判据、同一个理由：空闲连接立刻换手，别让它变僵尸。
    #[allow(clippy::too_many_arguments)]
    pub fn register_with_grace(
        &self,
        agent_id: String,
        peer_ip: IpAddr,
        models: Vec<String>,
        max_concurrency: u32,
        conn: s2n_quic::connection::Handle,
        close_grace: Duration,
        on_superseded_closed: Option<crate::evict_close::CloseObserver>,
    ) -> usize {
        let peer_ip = normalize_ip(peer_ip);
        let key = AgentKey::new(&agent_id, peer_ip);
        let stable_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        // 写锁下只碰 map（与 `evict` 同一条纪律）：被顶替的那条连接的关闭动作留到锁外，
        // 免得把传输调用夹在守卫里。
        let superseded = {
            let mut inner = write_or_recover(&self.inner);
            // `stable_id` 是本调用刚发的新号（单调、永不复用），表里那条一定属于**另一条**
            // 连接，所以"条目存在"与"它被顶替"是同一件事——早期版本在这里又比了一次
            // `old.stable_id != stable_id`，那是恒真条件（读起来像在防误关，其实什么都没防）。
            let superseded = match inner.get(&key) {
                Some(old) => {
                    warn!(
                        agent = %agent_id,
                        ip = %peer_ip,
                        "duplicate (agent_id, ip) connection, closing old one"
                    );
                    // 锁内**只取句柄与计数**（不调传输、不 spawn），关闭时机留到锁外决定。
                    Some((old.conn.clone(), old.inflight.clone(), old.agent_id.clone()))
                }
                None => None,
            };
            // **接管时继承在途计数**（复用同一个 `Arc`），不能给新条目发一个新的计数器：
            // 换连接之前取到的 `SlotGuard` 持有的是**旧那个 `Arc`**，而每个在途请求都靠它计数。
            // 新开一个计数器会让"已经送达上游、模型正在生成"的那些请求**不再被新条目看见**——
            // 新条目的 `inflight` 从 0 起算，而 drain 等待的正是这个数 ⇒ 上一条连接会被**立刻**
            // 关掉（正是本改动要修的那件事），忙/死判据与 `/admin/agents` 的在途数也一起偏低。
            // 逻辑上也没变：在途请求属于**这个节点**，不属于某一条 TCP/QUIC 连接。
            let inflight = match &superseded {
                Some((_, old_inflight, _)) => old_inflight.clone(),
                None => Arc::new(AtomicU32::new(0)),
            };
            inner.insert(
                key,
                Entry {
                    conn,
                    stable_id,
                    agent_id,
                    peer_ip,
                    models,
                    max_concurrency,
                    inflight,
                    open_timeouts: Arc::new(AtomicU32::new(0)),
                    head_timeouts: Arc::new(AtomicU32::new(0)),
                    tunnel_write_failures: Arc::new(AtomicU32::new(0)),
                    // 注册不是"活着"的证据：注册只说明连接建起来了，而这条判据问的是
                    // "**响应头**最近有没有流动"。所以从 NEVER 开始——一条注册后从不回响应头的
                    // 坏隧道必须能被原来的连续 3 次规则摘掉，不能因为"刚注册"而获得宽限
                    // （这条正是既有 e2e `e2e_dead_tunnel_fails_fast_instead_of_hanging` 钉住的）。
                    last_head_ok: Arc::new(AtomicU64::new(NEVER)),
                    last_seen_millis: Arc::new(AtomicU64::new(now_millis())),
                    // 注册**不算**"对端说过话"：初值 NEVER，等真收到心跳才算。
                    last_heartbeat_millis: Arc::new(AtomicU64::new(NEVER)),
                },
            );
            superseded
        };
        if let Some((old_conn, old_inflight, old_agent_id)) = superseded {
            let inflight = old_inflight.load(Ordering::Relaxed);
            // **判据是 `== 0`，不是 `<= 1`**：接管路径与 `evict` 的调用者不同——`evict` 是在
            // 一个**持有槽位**的请求上下文里被调用的（那个 1 就是它自己），而接管来自控制面
            // （`quic::handle_conn_inner` 的 `Register` 分支），调用者**不占任何请求槽位**。
            // 所以这里 `inflight == 1` 意味着**真有一个在途请求**，它必须被 drain 而不是被立刻关掉
            // （把 `<= 1` 从 `evict` 抄过来的话，恰好会关掉"只有一个在途请求"的那条连接——
            // 也就是最常见的那一种，drain 机制等于形同虚设）。
            if inflight == 0 {
                // 空连接 → 立刻关，让 agent 察觉并收敛到新连接。
                // （**保持同步关闭**：`defer_close` 即使 inflight==0 也是异步的，改过去会让
                // "空闲接管"的关闭时机白白延后一个 tick。）
                old_conn.close(0u32.into());
                if let Some(notify) = &on_superseded_closed {
                    notify();
                }
            } else {
                warn!(
                    agent = %old_agent_id,
                    ip = %peer_ip,
                    inflight,
                    grace_secs = close_grace.as_secs(),
                    "agent node took over an old connection; deferring its close until in-flight requests drain"
                );
                crate::evict_close::defer_close(
                    old_conn,
                    old_inflight,
                    &old_agent_id,
                    close_grace,
                    on_superseded_closed,
                );
            }
        }
        stable_id
    }

    /// 刷新某条条目的心跳时刻 —— **仅当它仍对应给定连接**（`stable_id`）；返回是否真的刷新了。
    ///
    /// **为什么必须比对连接**：`agent_id` 是帧里自报的（证书没有绑定它，见 `CERT_MANAGEMENT.md`），
    /// 而每条心跳都是一条独立的控制流。不加这层绑定的话，任何持合法证书的 agent 都能用**别人的**
    /// `agent_id` 发心跳，替一条已经死掉的条目**永久续命**——网关于是持续把请求路由到那台机器，
    /// 而且日志里毫无痕迹（不像顶替会打 `duplicate agent connection`）。
    /// 与 [`Self::remove_if_same`] 同一条纪律：**帧里的 id 不足以确定"你是谁"**。
    ///
    /// **只取读锁**：刷新心跳只是往一个原子量里写毫秒数，不需要独占整张表。以前这里用
    /// `write()` + `get_mut()`，因为 `Instant` 不是原子类型、只能靠可变借用来写——代价是
    /// 每来一帧心跳（agent 侧每 5s 一帧，多 agent 时叠加）就把**所有正在选路的读锁**挡在门外。
    /// 换成原子毫秒后，这个热点不再与路由争锁。
    ///
    /// `peer_ip` 参与查找：同名的两个节点各有自己的条目，心跳必须落在**本连接**那一条上
    /// （`stable_id` 才是最终判据；IP 只是把查找收窄到正确的键）。
    pub fn heartbeat_if_same(&self, agent_id: &str, peer_ip: IpAddr, stable_id: usize) -> bool {
        let key = AgentKey::new(agent_id, peer_ip);
        if let Some(e) = read_or_recover(&self.inner).get(&key) {
            if e.stable_id == stable_id {
                let now = now_millis();
                e.last_seen_millis.store(now, Ordering::Relaxed);
                // 同时也是"对端说过话"的证据：响应头静默判据的第二层靠它（见 `Entry::peer_alive`）。
                e.last_heartbeat_millis.store(now, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// 仅当条目仍对应给定连接（stable_id）时才移除，防止误删新连接的同名条目。
    ///
    /// 按 `(agent_id, peer_ip)` 定位：同名的两个节点是两条独立条目，本连接只能摘自己那条。
    /// 判据仍是 `stable_id`（IP 只是键的一半）。
    pub fn remove_if_same(&self, agent_id: &str, peer_ip: IpAddr, stable_id: usize) {
        let key = AgentKey::new(agent_id, peer_ip);
        let mut inner = write_or_recover(&self.inner);
        if let Some(e) = inner.get(&key) {
            if e.stable_id == stable_id {
                inner.remove(&key);
                info!(agent = %agent_id, ip = %key.peer_ip, "agent removed (connection closed)");
            }
        }
    }

    /// 同一原因的连续隧道失败阈值：达到它才认为"这条连接真的死了"。
    ///
    /// 取 3 而不是 1：单次失败在高并发下是**排队假象**——开流/写帧都要过连接级流管理器，
    /// 768 并发时很容易超过 `tunnel_op_secs`。实测（2026-09-17，双 agent/768 并发）：
    /// 第一次超时就把条目摘掉，而连接其实完好、agent 也毫不知情，于是每 5s 心跳继续
    /// 刷新心跳时刻（那时注册表里已经没有它）、所有请求 `503 registry-empty`（占比 92.6%）。
    ///
    /// 阈值对**每一种原因**各自适用（内部按 `EvictCause` 分开记；对外的入口是
    /// [`Registry::report_open_timeout`] 等四个方法）。
    pub const TUNNEL_TIMEOUTS_BEFORE_EVICT: u32 = 3;

    /// 一次**成功收到响应头**：清掉全部连续失败计数，并记下"这条隧道最近真的在干活"。
    ///
    /// 为什么一次成功要清三种计数：一次真正回来的响应头证明的是"这条隧道现在是通的"，
    /// 对开流、写帧、响应头三条判据都是同一份证据。唯一的调用点在响应头那一支
    /// （`proxy/mod.rs`）——**开流或写帧成功不算**：agent 卡死时流照样能开、帧也照样写得出去，
    /// 只是永远不回帧。
    ///
    /// **这里是按 `stable_id` 的全表扫描**（`:238` 与 `evict` 的查找同理）：map 以 `agent_id`
    /// 为键，而这条路径手上只有 `stable_id`。暂时不改成双索引：生产上 `n` 只有 1–4 个 agent
    /// （云端实测 `hlmg_agents 1`），扫 4 个元素远比它旁边那次 HTTP 往返便宜。真要动它，
    /// 先拿 profiling 说话（评估 §2 C4 的结论也是"别在没数据时动"）。
    pub fn note_tunnel_op_ok(&self, stable_id: usize) {
        let inner = read_or_recover(&self.inner);
        if let Some(e) = inner.values().find(|e| e.stable_id == stable_id) {
            e.open_timeouts.store(0, Ordering::Relaxed);
            e.head_timeouts.store(0, Ordering::Relaxed);
            e.tunnel_write_failures.store(0, Ordering::Relaxed);
            // 顺手记下"这条隧道最近真的回过响应头"——响应头超时的"忙/死"判据靠它。
            e.last_head_ok.store(now_millis(), Ordering::Relaxed);
        }
    }
    pub fn len(&self) -> usize {
        read_or_recover(&self.inner).len()
    }

    /// 注册表里 **心跳未过期** 的 agent 数（= 真正能被路由的候选数）。
    ///
    /// 与 [`Self::len`] 的区别很要紧：条目要等连接真正关闭才摘除，所以失联 agent
    /// 会继续被 `len()`（以及 `/metrics hlmg_agents`、`/admin/agents`）算作"在线"，
    /// 但它**不参与路由**。排查"所有请求 503"时必须能区分这两者——否则会误判为
    /// "agent 掉了"，实际是"注册表里有、但全部不健康"。
    pub fn healthy_count(&self, stale_after: Duration) -> usize {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        inner
            .values()
            .filter(|e| is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after))
            .count()
    }

    /// 挑不出候选时的诊断快照（只用于失败路径的日志/指标，不进热路径）。
    pub fn status(&self, stale_after: Duration) -> RegistryStatus {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut healthy = 0usize;
        let mut oldest: Option<Duration> = None;
        for e in inner.values() {
            let last = e.last_seen_millis.load(Ordering::Relaxed);
            let age = Duration::from_millis(since_millis(last, now));
            if is_fresh(last, now, stale_after) {
                healthy += 1;
            }
            oldest = Some(match oldest {
                Some(o) if o >= age => o,
                _ => age,
            });
        }
        RegistryStatus {
            registered: inner.len(),
            healthy,
            oldest_last_seen_ago: oldest,
        }
    }

    /// 注册表是否为空。
    ///
    /// **看起来没人调用，但删不得**：clippy 的 `len_without_is_empty` 是**默认开启**的，
    /// 一个公开类型有 `pub fn len` 却没有 `is_empty` 就会告警（实测：删掉它会得到
    /// `struct Registry has a public len method, but no is_empty method`，而 CI 跑的是
    /// `clippy -- -D warnings`）。它是与 [`Self::len`] 配对存在的方法，不是死代码。
    pub fn is_empty(&self) -> bool {
        read_or_recover(&self.inner).is_empty()
    }

    /// 返回全部已注册 agent 的明细快照（按 `(agent_id, ip)` 排序）。
    ///
    /// `stale_after` 决定每条的 `healthy`（与选路同一个判据，见 [`AgentInfo::healthy`]）；
    /// 调用方传 `AppState::agent_stale_after`。
    ///
    /// 排序键含 `ip`（而不只是 `agent_id`）：同名两个节点并存时，只按 id 排的相对次序是
    /// **未定义**的，而稳定序被前端 key、测试断言与人眼比对共同依赖。
    pub fn snapshot(&self, stale_after: Duration) -> Vec<AgentInfo> {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut out: Vec<AgentInfo> = inner
            .iter()
            .map(|(k, e)| {
                let last_seen = e.last_seen_millis.load(Ordering::Relaxed);
                AgentInfo {
                    // 取键里的那份（键与 `Entry` 同值，但键在 map 迭代里天然可用）
                    agent_id: k.agent_id.clone(),
                    ip: k.peer_ip.to_string(),
                    models: e.models.clone(),
                    max_concurrency: e.max_concurrency,
                    inflight: e.inflight.load(Ordering::Relaxed),
                    last_seen_secs_ago: since_millis(last_seen, now) / 1000,
                    healthy: is_fresh(last_seen, now, stale_after),
                }
            })
            .collect();
        // 稳定序：先 id 后 ip（两者都是字符串序，确定性够用，不引入 IP 数值序的额外语义）。
        out.sort_by(|a, b| (&a.agent_id, &a.ip).cmp(&(&b.agent_id, &b.ip)));
        out
    }

    /// 聚合所有**健康** agent 显式声明的模型（去重、排序）。
    /// `["*"]` 不贡献条目（全匹配，但具体能跑什么只有上游知道）。
    pub fn healthy_models(&self, stale_after: Duration) -> Vec<String> {
        let inner = read_or_recover(&self.inner);
        let now = now_millis();
        let mut out: Vec<String> = inner
            .values()
            .filter(|e| is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after))
            .flat_map(|e| e.models.iter().filter(|m| m.as_str() != "*").cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

impl Registry {
    /// 在**能服务指定模型**的健康 agent 中挑选一个并原子占用并发槽位；
    /// 返回的 [`SlotGuard`] 期间该请求计入在途数。
    ///
    /// 模型匹配语义：agent 声明的 `models` 含 `"*"`（全匹配/兜底）或含 `model`。
    /// 优先级：**精确声明该模型者优先于仅 `*` 通配者**（通配是兜底，不抢单）；
    /// 同级内按负载最轻优先，同等负载取最近心跳者（多 agent 均衡）。
    ///
    /// **生产路径走的是 [`Self::try_acquire_excluding`]**：`routing.rs` 总要把"刚失败的那条
    /// 连接"排除掉（否则重试没有意义），所以本方法在 `crates/gateway/src` 里没有调用者。
    /// 它是**单测的便利入口**（24 处调用，省掉一个 `&[]`），因此收进 `#[cfg(test)]`：
    /// 不进非测试构建，也不占 `Registry` 的公开 API（评估 §7 步骤 6 的"死 API"清理）。
    #[cfg(test)]
    pub fn try_acquire(
        &self,
        stale_after: Duration,
        model: &str,
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        self.try_acquire_excluding(stale_after, model, &[])
    }

    /// 同 `try_acquire`（测试便利入口，见下），但**跳过 `exclude` 里列出的连接**（按 `stable_id`）。
    ///
    /// 用于"换一个 agent 重试"：刚失败的那条连接不该再被选中（否则重试没有意义）。
    pub fn try_acquire_excluding(
        &self,
        stale_after: Duration,
        model: &str,
        exclude: &[usize],
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = read_or_recover(&self.inner);
        // 规则全在 [`pick`] 里（纯函数）：这里只负责"按序号占位、占不到就换下一个"。
        let candidates = pick(inner.values(), now_millis(), stale_after, model, exclude)?;
        for candidate in candidates {
            let entry = candidate.clone();
            // `max_concurrency == 0` = 不限：**不做上限判定**，但自增必须照做。
            // `inflight` 不只是准入闸门，它同时是另外三处的输入：开流超时的忙/死判据
            // （[`Entry::open_timeout_is_fatal`]，`0` 时以端点流额度为上限）、摘除时
            // "是否还有别人在途"（[`Registry::evict`] 的 `inflight <= 1`）、以及下面
            // `sort_by_key` 的负载排序键。
            //
            // 曾经写成 `entry.max_concurrency == 0 || …fetch_update(…)`：短路使"不增"，
            // 而 `SlotGuard::drop` 仍然"减" → `AtomicU32` 下溢回绕成 4294967295。
            // 后果是开流判据对该连接永久失效、每次摘除都白等满宽限期、这台 agent 永远排
            // 最后、`/admin/agents` 显示天文数字。回归测试：
            // `max_concurrency_zero_always_acquires_and_still_counts_inflight`。
            //
            // 用 `try_update` 而不是 `fetch_update`：后者在 nightly 1.100.0 起被标记为
            // `deprecated: renamed to try_update for consistency`（纯改名，签名与返回值
            // 语义一致），`try_update` 在 stable 1.97.1 就有（见 `TODO.md` 的那条）。
            let acquired = if entry.max_concurrency == 0 {
                let _ = entry.inflight.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                entry
                    .inflight
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        (n < entry.max_concurrency).then_some(n + 1)
                    })
                    .is_ok()
            };
            if acquired {
                let guard = SlotGuard(entry.inflight.clone());
                return Ok((entry, guard));
            }
        }
        Err(AcquireError::AtCapacity)
    }
}

/// 拒绝请求时的注册表诊断快照（仅日志/指标用）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryStatus {
    /// 注册表条目数（含失联但连接未关的）。
    pub registered: usize,
    /// 心跳未过期、真正可路由的条目数。
    pub healthy: usize,
    /// 最久没有心跳的条目距今多久（None = 注册表为空）。
    pub oldest_last_seen_ago: Option<Duration>,
}
