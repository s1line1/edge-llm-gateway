//! 注册表里的一条 agent 连接（[`Entry`]）与它的健康判据。
//!
//! 从这里切出来的理由：这是**唯一**持有传输句柄（`s2n_quic::connection::Handle`）的类型，
//! 而它的字段私有化、判据方法化，是注册表能在自己边界内保证不变量的全部依据。
//! 时钟（进程相对毫秒）与 `NEVER` 哨兵也只在这个模块里出现——调用方拿到的说法是
//! `last_head_ago() -> Option<Duration>`，不是那个哨兵值。

// 只为 rustdoc 链接解析而引入（`[`Registry::register`]` 这类跨模块文档链接）：
// 本体没有使用，故显式 allow，别把这个 import 当死代码删掉。
#[allow(unused_imports)]
use super::Registry;

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// 注册表里的一条 agent 连接：身份 + 传输句柄 + 健康计数。
///
/// **字段全部私有**（`pub(super)` 只是让父模块 `registry` 能构造与记账；对 crate 外不可见），
/// 外部只能通过只读访问器（[`Entry::stable_id`]、[`Entry::agent_id`]、
/// [`Entry::max_concurrency`]、[`Entry::inflight`]、[`Entry::open_stream`]）与判据方法看它。
/// 为什么必须这样：`try_acquire` 会把 `Entry` **克隆出去**给调用方长期持有（响应结束前都在），
/// 而克隆里的 `Arc<Atomic*>` 与注册表里那份是**同一块内存**——字段一旦可写，
/// 任何持有者都能改在途数、改计数、甚至关掉这条连接，注册表就没法在自己的边界内保证
/// "连续失败计数"这类不变量了。访问器给的是值（`usize`/`u32`/`&str`）或受控动作
/// （[`Entry::open_stream`]），不是那块内存本身。
#[derive(Debug, Clone)]
pub struct Entry {
    pub(super) conn: s2n_quic::connection::Handle,
    pub(super) stable_id: usize,
    /// 注册时的 agent_id。`try_acquire` 只交出 `Entry`（HashMap 的 key 不在其中），
    /// 而隧道写超时后需要按 stable_id 把这条坏连接摘掉（内部走 `Registry::evict`），
    /// 所以 id 必须随条目一起带出来。
    pub(super) agent_id: String,
    /// 这条连接在 socket 上看到的**来源 IP**（已归一，见 [`super::table::normalize_ip`]）。
    ///
    /// 与键 `(agent_id, peer_ip)` 里的那一份**同值**：键不参与 `Entry` 的克隆，而日志、
    /// `/admin/agents` 与"IP 变动"判据都要在只有 `Entry` 的地方说出"它从哪来"，所以值里
    /// 自带一份。**不含端口**：端口每次重连都会变，带上它会让接管永不触发。
    pub(super) peer_ip: IpAddr,
    pub(super) models: Vec<String>,
    pub(super) max_concurrency: u32,
    /// 当前在途请求数（admission control）。
    pub(super) inflight: Arc<AtomicU32>,
    /// 最近一次心跳的时刻（自 `epoch` 起的毫秒数）。
    ///
    /// 与 `last_head_ok` **共用同一个时间基准**。早先这里存 `Instant`、那边存相对毫秒：
    /// 两套时钟并存时"心跳新鲜"与"响应头新鲜"没法直接对账，而且 `Instant` 不是原子类型，
    /// 只能靠写锁 + `get_mut` 才能改——于是每来一帧心跳都要独占整张表（见
    /// [`Registry::heartbeat_if_same`]）。换成原子毫秒之后这两件事一起解决。
    ///
    /// 用 `Arc` 包一层是为了让 `Entry: Clone`（`AtomicU64` 自身不是 `Clone`），与同结构里
    /// `inflight` / 三个 strike 计数 / `last_head_ok` 保持同一种形状。
    pub(super) last_seen_millis: Arc<AtomicU64>,
    /// **收到过心跳**的时刻（自 `epoch` 起的毫秒数）；初值 `NEVER` = 从未收到过。
    ///
    /// 与 `last_seen_millis` 刻意分开：那个在注册时就写了一次（"刚注册的 agent 可以立刻
    /// 参与路由"）。而"对端还活着吗"要的是**它说过话**这个事实——注册本身不算说话。
    /// 用途见 [`Entry::peer_alive`]（响应头静默判据的第二层）。
    pub(super) last_heartbeat_millis: Arc<AtomicU64>,
    /// 连续"**开流**超时且判定为死"的次数（判据见 [`Entry::open_timeout_is_fatal`]）。
    ///
    /// **每一种失败原因各有一条计数**（开流 / 响应头 / 写帧失败）：混在一起时，三种
    /// **不同**的轻微失败会凑满同一个阈值，把一条其实健康的连接摘掉；而且一种失败达到
    /// 阈值后，另一种的"连续"语义会被无声改写。
    pub(super) open_timeouts: Arc<AtomicU32>,
    /// 连续"**响应头**静默超时"的次数（判据见 [`Entry::head_timeout_is_fatal`]）。
    pub(super) head_timeouts: Arc<AtomicU32>,
    /// 连续"**写请求帧直接失败**"的次数。
    ///
    /// 只有"写直接返回错误"计这里；**写超时不计**——那是连接级背压（共享发送缓冲/拥塞），
    /// 不是隧道死亡。写帧超时的死亡检出交给开流与响应头两条判据。
    pub(super) tunnel_write_failures: Arc<AtomicU32>,
    /// **最近一次真的收到响应头**的时刻（自 `epoch` 起的毫秒数）。
    ///
    /// 初值是 `NEVER`（从未收到过）。**注册不算"活着"**：注册只证明连接建起来了，
    /// 而这条判据问的是响应头有没有在流动。
    ///
    /// 为什么要单独记它：上面那几条计数只回答"连续失败了几次"，回答不了
    /// "这条隧道最近还干不干活"。链路被堵住时是"一个响应头都收不到"，于是计数必然爬到阈值，
    /// 把**健康但被堵住**的 agent 摘掉（实测：出口 0.4 MB/s 饱和时 1 026 次
    /// `upstream head timeout; evicting agent`，随后全量 503）。有了这个时间戳，
    /// 响应头超时就能像开流超时那样区分"忙/慢"与"死"（见 [`Entry::head_timeout_is_fatal`]）。
    pub(super) last_head_ok: Arc<AtomicU64>,
}

/// "从未收到过响应头"的哨兵值。
///
/// 不能用 0 当"从未"：时间基准是**首次使用时才创建**的，进程刚起来那一瞬间
/// `now_millis()` 就是 0，会和"从未"撞在一起。`u64::MAX` 不可能被真实时间戳取到。
pub(super) const NEVER: u64 = u64::MAX;

/// 时间基准：进程内单调时钟的原点（`Instant` 不能放进原子变量，所以存相对毫秒）。
fn epoch() -> std::time::Instant {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}

/// 自 `epoch` 起的毫秒数（用于 `last_head_ok` 这类无锁时间戳）。
///
/// **内部函数**：对外只通过 [`Entry::last_head_ago`] 暴露"安静了多久"，进程相对时钟与
/// `NEVER` 哨兵都不出注册表。
pub(super) fn now_millis() -> u64 {
    epoch().elapsed().as_millis() as u64
}

/// 距上次心跳过了多久（毫秒）。
pub(super) fn since_millis(last_seen_millis: u64, now_millis: u64) -> u64 {
    now_millis.saturating_sub(last_seen_millis)
}

/// 心跳是否仍在新鲜期内（= 这条条目参与路由与模型聚合）。
///
/// **这条判据原先在五个地方各写一遍**（`healthy_count`、`status`、`snapshot`、
/// `try_acquire_excluding`、`healthy_models`）。口径一旦分叉，"可路由的 agent 数"与
/// "选路时真正被过滤掉的数量"就对不上——而这两个数正是排查"所有请求 503"时唯一能互相
/// 对照的东西（见 `hlmg_agents` 与 `hlmg_agents_healthy` 的 HELP）。
pub(super) fn is_fresh(last_seen_millis: u64, now_millis: u64, stale_after: Duration) -> bool {
    since_millis(last_seen_millis, now_millis) < stale_after.as_millis() as u64
}

/// 「响应头静默」判据需要的三个时间窗。
///
/// 三个都是 `Duration`、语义却完全不同（窗口 / 对端活着 / 静默上限），所以用结构体传而不是
/// 三个位置参数——顺序写错不会有任何编译错误，只会让判据悄悄变松或变紧。
#[derive(Debug, Clone, Copy)]
pub struct HeadSilence {
    /// "忙/死"窗口：这么久内有过成功响应头就只是慢。= `head_timeout × 4`。
    pub window: Duration,
    /// "对端还活着"的判据：心跳在这个时间内 = 它还在说话。= `agent_stale_after`。
    pub peer_alive_window: Duration,
    /// 对端活着时，静默最多可以被宽限到多久。= `Options::head_silent_grace`（默认一条请求的寿命）。
    pub stuck_after: Duration,
}

/// 一次隧道失败的原因。[`Registry::evict`] 按它**分别**计连续次数，互不充值对方的阈值。
///
/// **内部类型**：调用方不再自己判断该记哪一种，而是通过 [`Registry::report_open_timeout`]、
/// [`Registry::report_open_failed`]、[`Registry::report_head_timeout`]、
/// [`Registry::report_write_failed`] 四个入口上报"发生了什么"，由注册表决定原因与后果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvictCause {
    /// 开流这条路失败：**超时且未达承载上限**（见 [`Entry::open_timeout_is_fatal`]），
    /// 或**直接返回错误**（见 [`Registry::report_open_failed`]）。两者在注册表看来是同一件事
    /// ——开不出流——所以共用这一条计数。
    OpenTimeout,
    /// 响应头静默超时 → 判定为死（见 [`Entry::head_timeout_is_fatal`]）。
    HeadTimeout,
    /// 写请求帧**直接失败**（非超时）→ 连接确已不可用。
    TunnelWriteFailed,
}

impl Entry {
    /// 这条条目的连接身份：进程内唯一、**永不复用**（见 [`Registry::register`] 的说明）。
    pub fn stable_id(&self) -> usize {
        self.stable_id
    }

    /// 注册时声明的 agent_id。
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// 这条连接看到的来源 IP（已归一、不含端口）。给日志与 `/admin/agents` 用。
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }

    /// agent 声明的并发上限（`0` = 不限）。只用于日志/展示。
    pub fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// 当前在途请求数。**含正在等响应头的那一类**（槽位从 `try_acquire` 取得，一直持有到
    /// 响应结束）。只给日志/展示用——判据请走 [`Self::open_timeout_is_fatal`]，
    /// 不要拿这个数自己推"忙还是死"。
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// 在这条连接上打开一条双向流。
    ///
    /// **超时策略不在这里**：多久算超时是 `Options::tunnel_op_timeout`，由调用方
    /// （`proxy::tunnel::open_tunnel`）用 `tokio::time::timeout` 包住。本方法的作用是把
    /// 传输句柄挡在注册表里面——否则每个想开流的模块都得拿到 `s2n_quic::connection::Handle`，
    /// 也就等于拿到了"关掉这条连接"的能力。
    ///
    /// 需要 `&mut self`：`s2n_quic::connection::Handle::open_bidirectional_stream` 自身就是
    /// `&mut self`（它在句柄内部记流状态）。这是唯一一处需要 `Entry` 可变借用的地方。
    pub async fn open_stream(
        &mut self,
    ) -> Result<s2n_quic::stream::BidirectionalStream, s2n_quic::connection::Error> {
        self.conn.open_bidirectional_stream().await
    }

    /// 一次「响应头超时」是否足以判定这条连接**已死**（该摘除）。
    ///
    /// 与 [`Entry::open_timeout_is_fatal`] 同一套思路，但问的是另一个问题：开流超时问
    /// "还有额度吗"，响应头超时问 **"这条隧道最近还在干活吗"**——因为响应头超时的两种成因
    /// 在现象上完全一样（`head_timeout` 内没等到头），区别只在于"是被堵住的慢"还是"真的没有了"。
    ///
    /// **两层口径**（第二层是 2026-09 为修"均匀慢流量"那条误判加的，见评估报告 §5 H2）：
    ///
    /// 1. `window` 内**有过**成功响应头 → 只是慢（返回 `false`，调用方只回 504、不计 strike）。
    /// 2. 窗口已过，但**对端还在说话**（心跳新鲜，见 `Entry::peer_alive`）且静默没超过
    ///    `stuck_after` → 仍然只是慢。为什么需要它：`last_head_ok` 的唯一刷新点就是成功响应头
    ///    本身，所以一旦**所有**请求都慢过 `head_timeout`（大模型首字节慢、上游排队、链路被堵），
    ///    就没有任何一次成功能刷新它，窗口必然走完 → 一条活得好好的 agent 被摘除 → 关连接 →
    ///    agent 重连 → 注册表为空 → 全量 503，**正是这条判据本来要防的那条链**（2026-09-18 实测）。
    ///    对端还在发心跳就说明它还在说话；而"数据面被堵住的慢"与"数据面卡死"在网关侧**观察上
    ///    无法区分**，这一层选择"宁可晚摘，不误摘"。
    /// 3. 其余 → 死：窗口已过，且（对端不再说话 **或** 静默已超过 `stuck_after`）。
    ///
    /// **"从未回过响应头"仍然是快路径**：没有成功响应头就**没有"它能服务"的证据**，于是不做
    /// 第 2 层的延长，直接交给连续 3 次摘除（既有 e2e
    /// `e2e_dead_tunnel_fails_fast_instead_of_hanging` 钉着这一点）。已知代价：一条**注册后
    /// 一次都没回包**、但还在心跳的连接（例如首字节一直慢过 `head_timeout`）仍会在 3 次之后
    /// 被摘除——这是这一层明确不覆盖的形态。
    ///
    /// 代价与兜底（第一层的旧账）：真死但"最近刚成功过"的 agent 会晚 `window` 才被摘除。
    /// 这不影响路由——真死的 agent 心跳会停，`agent_stale_after` 会先把它从候选里剔掉；
    /// 而进程直接消失时，QUIC 连接关闭会走 `remove_if_same` 正常摘除，根本不经过这里。
    /// 第二层的代价：一条**心跳正常但数据面卡死**的连接要等到静默超过 `stuck_after`
    /// （默认一条请求的寿命）才会被摘除，这期间它的每个请求都要白等一次 `head_timeout` 再拿 504。
    pub fn head_timeout_is_fatal(&self, ctx: HeadSilence) -> bool {
        let silence = self.last_head_ago();
        let Some(silence) = silence else {
            // 从未回过响应头：无"它能服务"的证据 → 快路径判死（见上）。
            return true;
        };
        if silence <= ctx.window {
            return false;
        }
        // 窗口已过。对端还在说话，且沉默还没到"一条请求的寿命"→ 更像被堵住，不摘。
        !(self.peer_alive(ctx.peer_alive_window) && silence <= ctx.stuck_after)
    }

    /// 对端最近还在说话吗：**收到过心跳**，且心跳在 `window` 内。
    ///
    /// 注意它与 `last_seen` **不是同一个问题**：`last_seen` 在注册时就写过一次（用于"刚注册
    /// 的 agent 可以立刻参与路由"），所以"注册时间戳很新"不能当成"对端还活着"。这里要的是
    /// "收到过心跳"这个**事实**，因此单独记 `last_heartbeat_millis`，初值 `NEVER`——一个注册后
    /// 什么都不做的对端（既有 e2e 里的"裸 agent"）永远不满足它。
    fn peer_alive(&self, window: Duration) -> bool {
        let hb = self.last_heartbeat_millis.load(Ordering::Relaxed);
        hb != NEVER && is_fresh(hb, now_millis(), window)
    }

    /// 距**最近一次真的收到响应头**过了多久；`None` = 从未收到过。
    ///
    /// 只给失败路径的日志用（"这条隧道到底安静了多久"）。把 `NEVER` 哨兵与进程相对时钟
    /// 都挡在注册表里面——调用方原先要自己 `now_millis() - last_head_ok.load(..)`，
    /// 那等于让每个调用方都知道哨兵的存在。
    pub fn last_head_ago(&self) -> Option<Duration> {
        let last = self.last_head_ok.load(Ordering::Relaxed);
        if last == NEVER {
            return None;
        }
        Some(Duration::from_millis(now_millis().saturating_sub(last)))
    }

    /// 一次「开流超时」是否足以判定这条连接**已死**（该摘除）。
    ///
    /// 为什么不能一律摘除：`open_bidirectional_stream()` 在**连接级流额度**排满时会
    /// 排队等回收（s2n-quic 的额度声明，实际可用取 `min(本地, 对端)`）。这条路径上的
    /// 超时既可能是"对端死了"，也可能只是"对端忙"：在途请求数已经顶到这条连接能承载的
    /// 上限时，排队超时是**正常背压**的表现。
    ///
    /// 把它一律当"死"的代价在云端实测过：上游一慢 → 开流排队超时 → 摘除**健康但繁忙**的
    /// agent → 连接被关 → agent 重连 → 注册表瞬间为空 → 其间所有请求 503
    /// （单次 30s 压测 +6835 次 `registry-empty`），是"局部过载"被放大成"全站不可用"。
    ///
    /// 判定口径：在途数是否已达到这条连接的实际承载上限
    /// （`min(声明的 max_concurrency, 端点流额度)`；`max_concurrency == 0` = 不限，
    /// 此时上限就是端点流额度）。达到 → 忙，不摘除；未达到 → 说明并不是没额度，
    /// 那就是真死了。
    pub fn open_timeout_is_fatal(&self, stream_ceiling: u32) -> bool {
        let ceiling = stream_ceiling.max(1);
        let effective = if self.max_concurrency == 0 {
            ceiling
        } else {
            self.max_concurrency.min(ceiling)
        };
        self.inflight.load(Ordering::Relaxed) < effective
    }
}
