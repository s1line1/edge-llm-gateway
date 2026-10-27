//! 网关可观测性指标：计数器与记录入口；准入票据在 `admission`，Prometheus 文本在 `render`。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::sync::lock_or_recover;

mod admission;
mod render;
pub use admission::{AcceptingGuard, Admission, AdmissionDomain};

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    /// 按 HTTP 状态码计数的请求数。
    status_counts: Mutex<HashMap<u16, u64>>,
    /// 当前在途请求数。
    active: AtomicU64,
    /// **受限域**在途数：只有 [`AdmissionDomain::Gated`] 的票据增减它，`max_concurrent_requests`
    /// 也只与它比较。
    ///
    /// 为什么不复用 `active`（复扫 A3）：`/healthz` 是**无认证**的豁免路径，却同样领票；探针
    /// （或对它的洪水）会把 `active` 抬到受限上限之上，让 `/v1` 全线 429，而探针自己仍是 200。
    active_gated: AtomicU64,
    /// **探针域**在途数：只有 [`AdmissionDomain::Probe`] 的票据增减它。
    active_probe: AtomicU64,
    /// **抓取域**在途数：只有 [`AdmissionDomain::Scrape`] 的票据增减它（复扫 A8）。
    ///
    /// 与探针域分开的理由同 `active_gated`：`/metrics` 也是**无认证**入口，共用探针域就等于
    /// "一轮抓取洪水能把 `/healthz` 顶成 429"，而 LB 会因此摘掉一个**健康**实例。
    active_scrape: AtomicU64,
    /// 转发给客户端的字节数。
    bytes_out: AtomicU64,
    /// 累计请求耗时（毫秒）。
    total_duration_ms: AtomicU64,
    /// 累计请求数（含 /metrics 之外的所有请求）。
    request_count: AtomicU64,
    /// **写出状态码之前**就被丢弃的请求数（客户端断开 / 连接被掐 / future 被 drop）。
    ///
    /// 为什么必须单独记：`request_count` 在准入成功时就 +1，而状态码是在处理返回之后才记的；
    /// 中断路径上后者永远不执行 → 仓库自用的"僵尸槽位"判据 `request_count − Σ状态码`
    /// 会**每个中断漂移 +1**，把真泄漏淹没。减掉这一项之后恒等式才重新可判
    /// （见 `render` 里 `hlmg_requests_aborted_total` 的 HELP 与 `README.md` 的排障一节）。
    aborted: AtomicU64,
    /// 公网入口 `accept()` 失败的次数（含 `EMFILE`/`ECONNABORTED`/`EINTR` 等暂时性错误）。
    ///
    /// 修复之前这类错误会让整个入口**永久停摆**（`accepted?` 结束循环），而进程、systemd
    /// 与其它入口全都正常；现在它会退避重试，这个计数就是"入口正在挣扎"的唯一信号——
    /// 持续增长说明 fd 长期不够用（`nofile.rs` 抬额度、`max_entry_connections` 或上游泄漏）。
    http_accept_errors: AtomicU64,
    /// 当前在线 QUIC 连接数（隧道层 gauge）。
    quic_connections: AtomicU64,
    /// 累计 agent 连接次数（重连计数，counter）。
    agent_connections_total: AtomicU64,
    /// QUIC 隧道入口是否仍在接受新连接（1/0）。入口停止后进程照常运行，这是唯一的告警信号。
    quic_accepting: AtomicU64,
    /// 响应转发的**退出原因**（kind → count，记录 P2-14）。
    ///
    /// 七条以上的出口里，大多数发生时**状态码已经写出去了**（200 已发给客户端，只是响应体
    /// 半截/空闲超时/上游断流），访问日志只记状态码 ⇒ 这类"客户端拿到半截回答"的失败本来
    /// 在生产上完全不可观测。kind 取自 `proxy::forward::ForwardEnd::label`（`&'static str`，
    /// 基数有界）。
    forward_ends: Mutex<HashMap<&'static str, u64>>,
    /// 因"挑不出可路由的 agent"而拒绝的请求数，按原因分（reason → count）。
    ///
    /// 与 HTTP 状态码计数是两件事：客户端只看到 503/404/429，而这里回答的是
    /// **为什么**——尤其是 `registry-empty`（真没人注册）与 `all-candidates-stale`
    /// （有人注册但心跳全过期）必须分开：两者都表现为 503，处置方式却完全不同。
    agent_rejections: Mutex<HashMap<&'static str, u64>>,
    /// "隧道建立失败后换 agent 重试"的次数，按结果分（ok = 重试成功，failed = 换过仍失败）。
    tunnel_retries: Mutex<HashMap<&'static str, u64>>,
    /// 客户端停滞而主动放弃的次数，按方向分（`request-body` = 请求体读不动、
    /// `response-body` = 客户端不消费响应体）。
    ///
    /// 这个计数是"准入槽位泄漏"的直接告警：修好之前，这类停滞不会留下任何痕迹，
    /// 只表现为 `hlmg_active_requests` 只增不减（实测云端沉淀 8 个，只能重启恢复）。
    client_stalls: Mutex<HashMap<&'static str, u64>>,
    /// **响应头**超时的次数，按判定分：`slow` = 最近还在正常回响应头（被堵住的慢，不摘除）、
    /// `silent` = 窗口内一次都没回过（判死，计入连续超时）。
    ///
    /// 与 `tunnel_open_timeouts` 分开是刻意的：那条问"还有额度吗"，这条问"最近还干活吗"，
    /// 两者混在一起就没法判断"该扩容还是该查网络"。
    head_timeouts: Mutex<HashMap<&'static str, u64>>,
    /// 开流超时的次数，按判定分：`busy` = 在途已顶到承载上限（背压，不摘除）、
    /// `dead` = 未到上限却开不出流（坏连接，摘除）。
    ///
    /// 这个区分是排障的关键：`busy` 陡增说明容量不足（该扩容或调 `max_concurrency`），
    /// `dead` 陡增才是隧道/网络故障。两者在状态码上都会表现为 5xx/429。
    tunnel_open_timeouts: Mutex<HashMap<&'static str, u64>>,
    /// 写请求帧失败的次数，按性质分：`backpressure` = 写超时（连接级背压，**不摘除**）、
    /// `broken` = 写直接返回错误（坏连接，计 strike）。
    ///
    /// 与 `tunnel_open_timeouts` 分开：那条量"开不出流"，这条量"帧写不进去"。
    /// `backpressure` 陡增说明 agent 读得慢或链路拥塞（该查 agent / 带宽），
    /// `broken` 陡增才是隧道/网络故障。两者原先都不区分，写超时被当成死亡。
    tunnel_write_failures: Mutex<HashMap<&'static str, u64>>,
}

impl Metrics {
    /// 当前在线 agent 连接数（`hlmg_quic_connections` 同一份读数）。
    pub fn quic_connections(&self) -> u64 {
        self.inner.quic_connections.load(Ordering::Relaxed)
    }

    /// 隧道入口是否仍在接受新连接（1/0）。
    pub fn quic_accepting(&self) -> u64 {
        self.inner.quic_accepting.load(Ordering::Relaxed)
    }

    /// 测试专用：直接置位「隧道入口接受中」（生产只走 [`Metrics::mark_accepting`] 的 Drop 守卫）。
    ///
    /// 存在的理由：`/healthz` 现在拿这个 gauge 当存活判据，而测试里的裸 `AppState`
    /// （`http::test_util::test_state`）没有真 QUIC 入口——不置位的话**所有**走 `/healthz`
    /// 的用例都会看到 503。
    #[cfg(test)]
    pub fn set_quic_accepting_for_test(&self, accepting: bool) {
        self.inner
            .quic_accepting
            .store(u64::from(accepting), Ordering::Relaxed);
    }

    /// 记录一次"无可路由 agent"的拒绝及其原因（原因常量见 `proxy` 的调用点）。
    pub fn record_agent_rejection(&self, reason: &'static str) {
        *lock_or_recover(&self.inner.agent_rejections)
            .entry(reason)
            .or_insert(0) += 1;
    }

    /// 记录一次"因隧道建立失败而换 agent 重试"及其结果。
    pub fn record_tunnel_retry(&self, outcome: &'static str) {
        *lock_or_recover(&self.inner.tunnel_retries)
            .entry(outcome)
            .or_insert(0) += 1;
    }

    /// 记录一次响应头超时（`kind`：`slow` = 还在回响应头，`silent` = 窗口内没有任何响应头）。
    pub fn record_head_timeout(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.head_timeouts)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次"客户端停滞 → 放弃"（`phase`：`request-body` / `response-body`）。
    pub fn record_client_stall(&self, phase: &'static str) {
        *lock_or_recover(&self.inner.client_stalls)
            .entry(phase)
            .or_insert(0) += 1;
    }

    /// 记录一次响应转发的退出原因（`kind` 见 `proxy::forward::ForwardEnd::label`）。
    pub fn record_forward_end(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.forward_ends)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次开流超时（`kind`：`busy` = 背压排队，`dead` = 坏连接）。
    pub fn record_tunnel_open_timeout(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.tunnel_open_timeouts)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记录一次写请求帧失败（`kind`：`backpressure` = 写超时，`broken` = 写直接失败）。
    pub fn record_tunnel_write_failure(&self, kind: &'static str) {
        *lock_or_recover(&self.inner.tunnel_write_failures)
            .entry(kind)
            .or_insert(0) += 1;
    }

    /// 记一次「被全局闸门拒掉」。**只补 `request_count`**：`try_enter` 失败时没有自增。
    ///
    /// 状态码**不在这里记**——闸门住在 id 中间件里层，被拒的 429 会经过外层，由外层统一
    /// `record_status`。两边各记一半，`request_count − Σ状态码 − aborted` 才平衡
    /// （在这里也记一次就会重复计数，恒等式反而变成 -1）。
    pub fn record_rejected(&self) {
        self.inner.request_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录请求结果状态码（在途槽位的释放不在此处，由 [`Admission`] 负责）。
    pub fn record_status(&self, status: u16) {
        *lock_or_recover(&self.inner.status_counts)
            .entry(status)
            .or_insert(0) += 1;
    }

    /// 记一次「请求在写出状态码之前被丢弃」。由 `metrics_middleware` 的 RAII 守卫调用
    /// （见 `http/observability.rs`）：取消没有"出口"可写，只有 Drop 能覆盖。
    pub fn record_aborted(&self) {
        self.inner.aborted.fetch_add(1, Ordering::Relaxed);
    }

    /// 记一次公网入口 `accept()` 失败（调用方已经退避重试，入口会继续监听）。
    pub fn record_accept_error(&self) {
        self.inner
            .http_accept_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 公网入口 `accept()` 累计失败次数。
    pub fn http_accept_errors(&self) -> u64 {
        self.inner.http_accept_errors.load(Ordering::Relaxed)
    }

    /// 三项供测试核对恒等式 `request_count − Σ状态码 − aborted == 0`（真泄漏才会让它 >0）。
    #[cfg(test)]
    pub fn identity_terms(&self) -> (u64, u64, u64) {
        let status_total: u64 = lock_or_recover(&self.inner.status_counts).values().sum();
        (
            self.inner.request_count.load(Ordering::Relaxed),
            status_total,
            self.inner.aborted.load(Ordering::Relaxed),
        )
    }

    pub fn add_bytes_out(&self, n: usize) {
        self.inner.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// 当前在途请求数（**全部域**；`hlmg_active_requests` 与 `drain()` 读它）。
    ///
    /// 注意它**不再是准入门槛**——判据在 [`Self::try_enter`] 里按域取（复扫 A3）。
    pub fn active_count(&self) -> u64 {
        self.inner.active.load(Ordering::Relaxed)
    }

    /// **受限域**在途数：准入门槛、拒绝日志与测试读它。
    pub fn active_gated_count(&self) -> u64 {
        self.inner.active_gated.load(Ordering::Relaxed)
    }

    /// **探针域**在途数（`/healthz`）：拒绝日志与测试读它。
    pub fn active_probe_count(&self) -> u64 {
        self.inner.active_probe.load(Ordering::Relaxed)
    }

    /// **抓取域**在途数（`/metrics`）：拒绝日志与测试读它（复扫 A8）。
    pub fn active_scrape_count(&self) -> u64 {
        self.inner.active_scrape.load(Ordering::Relaxed)
    }

    /// agent 连接建立：累计 +1、当前在线 +1。
    pub fn mark_agent_connected(&self) -> AgentConnectionGuard {
        self.inner
            .agent_connections_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.quic_connections.fetch_add(1, Ordering::Relaxed);
        AgentConnectionGuard(self.clone())
    }

    /// agent 连接断开：当前在线 -1。**只由 [`AgentConnectionGuard`] 调用**。
    ///
    /// 饱和减而不是裸 `fetch_sub`：gauge 在 0 上回绕会变成 `u64::MAX`（`hlmg_quic_connections`
    /// 永远报警）。守卫已经保证每 +1 恰好配一次 -1，这里是第二道保险——一处逻辑错误不该把
    /// 仪表盘彻底毁掉。
    fn agent_disconnected(&self) {
        let _ = self
            .inner
            .quic_connections
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

/// 一条 agent 连接的生命周期守卫：见 [`Metrics::mark_agent_connected`]。
///
/// **为什么必须用 Drop**（评估记录 P2-11）：以前 `quic.rs` 是在连接任务里"先 +1、末尾 -1"，
/// 而 `handle_conn` 里任何 panic 都会让末尾那句不执行——`hlmg_quic_connections` 于是**永久虚高**，
/// 而且注册表条目也再也摘不掉（没有 stale 清扫器）。仓库其它资源（`AcceptingGuard` /
/// `Admission` / `SlotGuard`）早就是这个模式，这是最后一处例外。
pub struct AgentConnectionGuard(Metrics);

impl Drop for AgentConnectionGuard {
    fn drop(&mut self) {
        self.0.agent_disconnected();
    }
}

#[cfg(test)]
mod tests;
