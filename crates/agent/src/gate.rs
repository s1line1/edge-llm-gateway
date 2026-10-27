//! 本机并发闸门 + 心跳观察：`max_concurrency` 不只是"告诉网关"，本机也执行它。
//!
//! 闸门与心跳必须放在同一个 `select!` 里观察（见 `acquire_slot` 的文档）：排队期间
//! 心跳失败/panic 若无人观察，连接不会被拆，agent 自认连着而网关全程 503。

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, warn};

/// 排队超过这个时长才算"闸门真的在起作用"（避免把准入与在途之间的瞬时竞态也记成排队）。
pub(crate) const SLOT_WAIT_LOG_AFTER: Duration = Duration::from_millis(100);
/// 持续过载时的日志节流间隔：这个项目的日志单日 652MB（`TODO.md` 已登记），不能每请求一行。
pub(crate) const SLOT_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 本机并发闸门（记录 P2-3）：`max_concurrency` 不只是"告诉网关"，**本机也执行它**。
///
/// 为什么需要（纵深防御）：正常路径上网关按它对注册表的登记卡住并发
/// （`try_acquire_excluding` 保证 `inflight < max_concurrency`），所以今天不出事。但只要
/// 网关那侧不守约——最现实的一条是 agent 配 `max_concurrency: 0`（网关侧 `0` 的语义是
/// **不限**）、其次是网关准入被改坏或被换成别的实现——本机就会把最多 **1000** 条并发流
/// （QUIC 流额度）全压进一台只按 4 个并发配置的本地 LLM：显存打满、首字节从 1–3s 崩到
/// 几十秒，而**两侧都不报错**，只是"变慢/超时"。
///
/// `max == 0` = **不限**（与网关侧语义一致）⇒ 不建闸门，此时唯一上限仍是 QUIC 流额度。
pub(crate) struct ConcurrencyGate {
    sem: Arc<Semaphore>,
    max: u32,
    /// 累计排队次数（只进日志，用来一行看出"防御持续生效了多久"）。
    queued: u64,
    /// 上次因排队打日志的时刻（节流用）。
    pub(crate) last_log: Option<Instant>,
}

impl ConcurrencyGate {
    /// `max == 0` = 不限 ⇒ `None`（没有闸门）。
    pub(crate) fn new(max: u32) -> Option<Self> {
        (max > 0).then(|| Self {
            sem: Arc::new(Semaphore::new(max as usize)),
            max,
            queued: 0,
            last_log: None,
        })
    }

    /// 取一个并发许可；满了就**排队等**。
    ///
    /// 为什么不在这里回 `Frame::Error`：网关的准入计数与"实际在途"之间有微小竞态，
    /// 瞬时超发一点点时排队就能救回来；回错误则变成**用户可见的假失败**（网关不会为这种
    /// 帧错误换 agent 重试）。等待的上界由网关自己给（`head_timeout` 到了它会给客户端 504，
    /// 而我们这边照旧把上游请求跑完/被 Cancel）。
    pub(crate) async fn acquire(&mut self) -> OwnedSemaphorePermit {
        let started = Instant::now();
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore 只在本结构里，且从不 close");
        if started.elapsed() >= SLOT_WAIT_LOG_AFTER {
            self.queued += 1;
            if self
                .last_log
                .is_none_or(|t| t.elapsed() >= SLOT_LOG_INTERVAL)
            {
                self.last_log = Some(Instant::now());
                warn!(
                    max_concurrency = self.max,
                    queued_total = self.queued,
                    wait_ms = started.elapsed().as_millis(),
                    "本机并发已达声明的 max_concurrency，请求在排队；网关侧的准入与实际在途不一致？"
                );
            }
        }
        permit
    }

    /// 供测试观察节流状态。
    #[cfg(test)]
    pub(crate) fn queued(&self) -> u64 {
        self.queued
    }
}

/// 取闸门许可的结果（复扫 E1）。
pub(crate) enum SlotOutcome {
    /// 拿到许可；`None` = 没开闸门（`max_concurrency = 0` = 不限）。
    Permit(Option<OwnedSemaphorePermit>),
    /// 等许可期间心跳结束了 —— 必须结束这条连接，交回 `run()` 重连。
    HeartbeatDown,
}

/// 取一个闸门许可，但**同时**盯着心跳（复扫 E1）。
///
/// 为什么必须放在 `select!` 里：`tokio::select!` 的分支体一旦 await，其它分支就不再被 poll。
/// 所以"在 accept 分支体里直接 `g.acquire().await`"会让**排队期间**心跳失败/panic 无人观察
/// ——连接不会被拆，agent 自认连着而网关全程 503（`run_connection` 顶部那段注释描述的静默态）。
///
/// 抽成独立函数是为了能直接测这条性质（见本文件测试里的
/// `waiting_for_a_slot_still_notices_a_dead_heartbeat`）：给一个许可已占满的闸门 + 一个已经
/// 结束的心跳，它必须**立刻**回 [`SlotOutcome::HeartbeatDown`]，而不是一直排队。
pub(crate) async fn acquire_slot(
    gate: &mut Option<ConcurrencyGate>,
    hb: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> SlotOutcome {
    let Some(g) = gate.as_mut() else {
        return SlotOutcome::Permit(None);
    };
    tokio::select! {
        r = &mut *hb => {
            report_heartbeat_down(r);
            SlotOutcome::HeartbeatDown
        }
        permit = g.acquire() => SlotOutcome::Permit(Some(permit)),
    }
}

/// 心跳任务结束时的统一处置（复扫 E1 把它从 `select!` 分支体里提出来）。
///
/// 提取的原因：下面 accept 循环里**有两处**要观察心跳——循环顶部，以及"等闸门许可"的那段。
/// 两处必须给出同一句日志，否则"哪种死法说什么话"就会随调用点漂移。
pub(crate) fn report_heartbeat_down(joined: Result<anyhow::Result<()>, tokio::task::JoinError>) {
    match joined {
        Ok(Ok(())) => warn!("heartbeat loop exited; forcing reconnect"),
        Ok(Err(e)) => warn!("heartbeat loop failed: {e}; forcing reconnect"),
        Err(e) if e.is_panic() => {
            error!("heartbeat loop panicked: {e}; forcing reconnect")
        }
        Err(e) => warn!("heartbeat task cancelled: {e}; forcing reconnect"),
    }
}
