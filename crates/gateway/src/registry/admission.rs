//! 并发准入：`SlotGuard`（RAII 归还槽位）与 `try_acquire*`（CAS 占位）。
//!
//! 规则（选谁）在 `routing::pick`；这里只负责"按候选顺序占位、占不到就换下一个"，
//! 以及槽位释放的 RAII 语义。`SlotGuard` 的 Drop 必须覆盖正常返回、`?` 提前返回与 panic。

use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use super::entry::{now_millis, Entry};
use super::routing::{pick_for_tenant, AcquireError};
use super::Registry;
#[cfg(test)]
use crate::storage::DEFAULT_TENANT_ID;
use crate::sync::read_or_recover;

/// Drop 时自动归还并发槽位。
pub(crate) struct SlotGuard(Arc<AtomicU32>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
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
    pub(crate) fn try_acquire(
        &self,
        stale_after: Duration,
        model: &str,
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        self.try_acquire_excluding(stale_after, model, &[])
    }

    /// 同 `try_acquire`（测试便利入口，见下），但**跳过 `exclude` 里列出的连接**（按 `stable_id`）。
    ///
    /// 用于"换一个 agent 重试"：刚失败的那条连接不该再被选中（否则重试没有意义）。
    #[cfg(test)]
    pub(crate) fn try_acquire_excluding(
        &self,
        stale_after: Duration,
        model: &str,
        exclude: &[usize],
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        self.try_acquire_excluding_for_tenant(DEFAULT_TENANT_ID, stale_after, model, exclude)
    }

    /// 只从指定 tenant 的 agent 中占位。
    pub(crate) fn try_acquire_excluding_for_tenant(
        &self,
        tenant_id: &str,
        stale_after: Duration,
        model: &str,
        exclude: &[usize],
    ) -> Result<(Entry, SlotGuard), AcquireError> {
        let inner = read_or_recover(&self.inner);
        // 规则全在 [`pick_for_tenant`] 里（纯函数）：这里只负责"按序号占位、占不到就换下一个"。
        let candidates = pick_for_tenant(
            inner.values(),
            now_millis(),
            stale_after,
            tenant_id,
            model,
            exclude,
        )?;
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
