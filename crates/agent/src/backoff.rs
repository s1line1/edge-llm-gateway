//! 重连退避与抖动：纯函数，脱离 QUIC/时钟即可单测。
//!
//! 这里的常数不是拍脑袋：`BACKOFF_RESET_AFTER` 专门区分"健康跑了很久后断开"与
//! "刚注册就被踢"，`BACKOFF_MAX` 与抖动上限见各常量的文档。

use std::time::Duration;

/// 重连退避基准（第一次重连等这么久）。
pub(crate) const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// 标称上限。DESIGN §6.1 原设计是"抖动 + 上限 60s"，这里刻意取 30s：网关滚动重启后
/// agent 回归更快；握手风暴的余地由 `connect_once` 里的 30s 握手限时给（那段注释解释了
/// 为什么不能更短）。
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// 会话活过这么久才算"健康"，断开时才把退避重置回基准。
///
/// 阈值存在的唯一理由是记录 P2-1 那个根因：`connect_once` 返回 `Ok(())` 有**两种**语义——
/// "健康跑了很久后断开" 与 "刚注册就被踢"（如同名 `agent_id` 互踢、网关注册后立刻关连接）。
/// 旧代码把两者都当成前者、退避一律重置回 500ms，于是每 ~500ms 互踢一次、永不收敛
/// （实测：3 秒内 5 次连接、6 个 `/v1/slow` 全 502，而两侧进程与 `/admin/agents` 都正常）。
/// 现在**只看会话活了多久**，与 Ok/Err 无关。
pub(crate) const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);
/// 抖动幅度（百分比）：多台 agent 同时断线（网关重启）时不要把重连挤在同一毫秒。
pub(crate) const BACKOFF_JITTER_PERCENT: u64 = 20;

/// 下一轮的标称退避：会话活得够久才重置，否则翻倍（封顶 [`BACKOFF_MAX`]）。
pub(crate) fn next_backoff(current: Duration, session_alive: Duration) -> Duration {
    if session_alive >= BACKOFF_RESET_AFTER {
        BACKOFF_BASE
    } else {
        std::cmp::min(current.saturating_mul(2), BACKOFF_MAX)
    }
}

/// 给标称退避加 ±[`BACKOFF_JITTER_PERCENT`]% 抖动，并**仍然封顶** [`BACKOFF_MAX`]
/// （顶上因此是单边缩小：一撮 agent 落在 `[24s, 30s]` 而不是同一个 30s）。
///
/// `entropy` 由调用方给：生产用时钟纳秒，测试直接喂值——策略是纯函数，才钉得住。
pub(crate) fn jittered(backoff: Duration, entropy: u64) -> Duration {
    let span = BACKOFF_JITTER_PERCENT * 2;
    let percent = 100 - BACKOFF_JITTER_PERCENT + (entropy % (span + 1));
    let micros = backoff.as_micros() * u128::from(percent) / 100;
    std::cmp::min(Duration::from_micros(micros as u64), BACKOFF_MAX)
}

/// 抖动的熵：不引入 `rand` 依赖（只为一个 ±20% 的抖动不值当），用时钟纳秒 + 秒数混合。
pub(crate) fn jitter_entropy() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) ^ d.as_secs())
        .unwrap_or(0)
}
