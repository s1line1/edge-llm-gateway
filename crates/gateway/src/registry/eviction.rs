//! 隧道失败的记账与摘除：`report_*` 四个入口 + [`evict`](Registry::evict)。
//!
//! 为什么独立成模块：这里的每个决定（记哪条 strike、什么时候摘、摘了之后立刻关还是等
//! 在途请求收尾）都是**注册表自己的策略**，而调用方（`proxy/routing.rs`、`proxy/head.rs`）
//! 只该问「发生了什么」，拿回一个 [`Disposition`] 去渲染。策略与渲染分家之后，"忙 ≠ 死"
//! 这条口径只有一个地方能改。

use std::{sync::atomic::Ordering, time::Duration};

use tracing::warn;

use super::entry::{Entry, EvictCause, HeadSilence};
use super::routing::Disposition;
use super::Registry;
use crate::sync::write_or_recover;

impl Registry {
    /// 上报一次「**开流超时**」，由注册表判定是**忙**还是**死**。
    ///
    /// 判据在 [`Entry::open_timeout_is_fatal`]：在途已达这条连接的承载上限 → 只是排队等额度
    /// （[`Disposition::Transient`]，**不记账**）；没到上限却开不出流 → 死。
    /// 返回 [`Disposition::Fatal`] 时**已经**记过一次 strike，连续到阈值时条目也已被摘除；
    /// 调用方只需把它映射成文案、指标标签与状态码。
    pub fn report_open_timeout(
        &self,
        entry: &Entry,
        stream_ceiling: u32,
        close_grace: Duration,
    ) -> Disposition {
        if entry.open_timeout_is_fatal(stream_ceiling) {
            self.evict(entry.stable_id, EvictCause::OpenTimeout, close_grace);
            Disposition::Fatal
        } else {
            Disposition::Transient
        }
    }

    /// 上报一次「**开流直接失败**」（不是超时）。没有"忙"这种可能，直接记账。
    pub fn report_open_failed(&self, entry: &Entry, close_grace: Duration) {
        self.evict(entry.stable_id, EvictCause::OpenTimeout, close_grace);
    }

    /// 上报一次「**响应头超时**」，由注册表判定是**慢**还是**死**。
    ///
    /// 判据在 [`Entry::head_timeout_is_fatal`]，**两层**：窗口内有过成功响应头 → 只是被链路或
    /// 上游堵住（[`Disposition::Transient`]，只回 504、**不计 strike**）；窗口过了但**对端还在
    /// 说话**（心跳新鲜）且静默没超过"一条请求的寿命" → 仍然算慢（这是 2026-09 为修"均匀慢流量"
    /// 那条误判加的，见评估 §5 H2）；其余 → 死。窗口与两个时限都由调用方从 `AppState` 传入
    /// （见 [`HeadSilence`]）。
    pub fn report_head_timeout(
        &self,
        entry: &Entry,
        silence: HeadSilence,
        close_grace: Duration,
    ) -> Disposition {
        if entry.head_timeout_is_fatal(silence) {
            self.evict(entry.stable_id, EvictCause::HeadTimeout, close_grace);
            Disposition::Fatal
        } else {
            Disposition::Transient
        }
    }

    /// 上报一次「**写请求帧直接失败**」（不是超时）。同样没有判据，直接记账。
    ///
    /// 写**超时**不走这里——那是连接级背压（同一条连接上的流共享发送缓冲/UDP socket），
    /// 见 `WriteFailure::is_tunnel_broken`。
    pub fn report_write_failed(&self, entry: &Entry, close_grace: Duration) {
        self.evict(entry.stable_id, EvictCause::TunnelWriteFailed, close_grace);
    }

    /// 记录一次隧道失败，并在**同一原因连续**达到阈值时摘除条目。
    ///
    /// **内部实现**：调用方走 [`Self::report_open_timeout`] / [`Self::report_head_timeout`] /
    /// [`Self::report_write_failed`]——那三个方法才是"判定 + 记账 + 摘除"的对外入口，
    /// 本方法只负责"给定原因就记一笔"这一层。
    ///
    /// `cause` 决定计哪一条连续计数（见 [`EvictCause`]）：不同原因的阈值互不充值——
    /// 否则三种不同的轻微失败会凑满一个阈值，把健康连接摘掉。
    ///
    /// 关键：摘除时**同时关闭连接**。只删条目不关连接会留下"僵尸"——agent 侧看不到
    /// 任何异常（心跳照通、连接照开），却永远无法再被路由；agent 只有等到自己判断
    /// 连接不可用才会重连，而那一刻可能永远不来。
    ///
    /// `close_grace` 是"移出路由之后最多再等多久就关连接"：由调用方从
    /// [`crate::Options::evict_close_grace`] 传入。与 `stale_after`、`stream_ceiling`、
    /// `window` 一样采取**每调用注入**——注册表自己不存配置。
    ///
    /// 返回是否真的摘掉了（false = 计数未达阈值，或条目已被别人摘掉/替换）。
    pub(super) fn evict(
        &self,
        stable_id: usize,
        cause: EvictCause,
        close_grace: Duration,
    ) -> EvictOutcome {
        // 写锁的范围**只够**做 map 与原子量的事：查找、计 strike、移出路由、读在途数。
        // 关闭连接与 spawn 调度一律留到锁外——`tokio::spawn` 若在守卫内 panic，守卫会在
        // unwind 中释放 → 锁**永久中毒**，之后每一次 register/heartbeat/选路都跟着 panic
        // （评估 §5 H3）。这条纪律对 `register` 同样适用。
        #[allow(clippy::type_complexity)]
        let (_key, agent_id, peer_ip, entry, n, inflight) = {
            let mut inner = write_or_recover(&self.inner);
            let hit = inner
                .iter()
                .find(|(_, e)| e.stable_id == stable_id)
                .map(|(k, e)| (k.clone(), e.clone()));
            let Some((key, entry)) = hit else {
                return EvictOutcome::NotFound;
            };
            // 日志里说的是**节点身份**（id + 来源 IP）：同名两个节点并存时，只打 id 无法区分
            // 是哪一条被摘除。
            let agent_id = key.agent_id.clone();
            let peer_ip = key.peer_ip;
            let strikes = match cause {
                EvictCause::OpenTimeout => &entry.open_timeouts,
                EvictCause::HeadTimeout => &entry.head_timeouts,
                EvictCause::TunnelWriteFailed => &entry.tunnel_write_failures,
            };
            let n = strikes.fetch_add(1, Ordering::Relaxed) + 1;
            if n < Self::TUNNEL_TIMEOUTS_BEFORE_EVICT {
                warn!(
                    agent = %agent_id,
                    ip = %peer_ip,
                    consecutive = n,
                    threshold = Self::TUNNEL_TIMEOUTS_BEFORE_EVICT,
                    cause = ?cause,
                    "tunnel failure; keeping the entry for now"
                );
                return EvictOutcome::BelowThreshold { consecutive: n };
            }

            // ① 先移出路由：后续请求不会再选中它（这一步与关闭时机无关）。
            inner.remove(&key);
            let inflight = entry.inflight.load(Ordering::Relaxed);
            (key, agent_id, peer_ip, entry, n, inflight)
        };

        // ② 再决定何时关闭连接。**不能立刻关**：这条连接上往往还有别的在途请求，
        //    而它们在 `inflight` 里有两类，**两类都不该被连带打断**：
        //      · 已经把请求完整送达 agent、模型正在生成的——早过了响应头那一关，
        //        不属于"建立阶段可重试"的范围，打断就是纯损失（客户白花钱还拿不到结果）；
        //      · **还在等响应头的**——槽位是从 `try_acquire` 取得、一直持有到响应结束的
        //        （`routing.rs` 取得 → `proxy/mod.rs` 的 `read_head` → `forward.rs` 持有），
        //        所以它们也在 `inflight` 里；它们并没有出错，只是还没轮到回包。
        //    所以在途归零后再关；超过宽限期也强制关，否则 agent 永远是僵尸。
        //    调度与期限都在 `crate::evict_close` 里（连同"宽限不得短于 head_timeout"那条约束）。
        if inflight <= 1 {
            // 只有当前这个失败请求占着槽位 → 关掉不会牵连别人。
            // 而且要**立刻**关，好让 agent 察觉并重连，别变回僵尸。
            entry.conn.close(0u32.into());
            warn!(
                agent = %agent_id,
                ip = %peer_ip,
                consecutive = n,
                cause = ?cause,
                "agent evicted (repeated tunnel failures); closing connection so one side notices"
            );
            EvictOutcome::RemovedClosed
        } else {
            warn!(
                agent = %agent_id,
                ip = %peer_ip,
                consecutive = n,
                inflight,
                grace_secs = close_grace.as_secs(),
                "agent evicted; deferring connection close until in-flight requests drain"
            );
            crate::evict_close::defer_close(
                entry.conn.clone(),
                entry.inflight.clone(),
                &entry.agent_id,
                close_grace,
                None,
            );
            EvictOutcome::RemovedClosedLater { inflight }
        }
    }
}

/// 摘除后的收尾方式。存在的意义有二：让**注册表内部与测试**能区分"立刻关闭"与"等在途收尾"，
/// 以及把"为什么不能立刻关"这件事写进类型里（见 [`Registry::evict`]）。
///
/// **内部类型**：对外只暴露 [`Disposition`]（"忙还是死"）。调用方今天没有任何一处需要知道
/// "这次是延迟关闭还是立刻关闭"——把它摆到公共接口上只会是没人消费的宽度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvictOutcome {
    /// 连续超时未达阈值：条目保留，只累计计数。
    BelowThreshold { consecutive: u32 },
    /// 已摘除且连接已立即关闭（没有别的在途请求会被牵连）。
    RemovedClosed,
    /// 已摘除，连接会在在途请求收尾后（或超过宽限期）关闭。
    RemovedClosedLater { inflight: u32 },
    /// 条目已不存在（被别人摘掉，或已被新连接替换）。
    NotFound,
}
