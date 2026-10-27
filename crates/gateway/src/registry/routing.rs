//! 选路：从当前条目里挑出候选，以及「挑不出人」时的拒绝理由。
//!
//! 规则本身是**纯函数**（[`pick`]）——它只读条目、不占槽位，所以可以脱离 PKI 与 QUIC 端点
//! 直接断言；占位（`inflight` 的 CAS）留在 [`super::Registry::try_acquire_excluding`] 里。

use std::{sync::atomic::Ordering, time::Duration};

use super::entry::{is_fresh, Entry};
#[cfg(test)]
use crate::storage::DEFAULT_TENANT_ID;

/// 一次隧道失败的**处置**：注册表判定，调用方只负责渲染。
///
/// 为什么是一个类型而不是 `bool`：三个调用点问的是同一个问题的三种问法——"还有额度吗"
/// （开流超时）、"最近还干活吗"（响应头超时）、"是不是直接失败了"（写帧）。判据只该存在
/// 一处，而**后果**（记哪条 strike、要不要摘除、要不要关连接）也只该由那一处决定。
/// 以前两个调用方各自把 `open_timeout_is_fatal` / `head_timeout_is_fatal` 与
/// `matches!(failure, TimedOut)` 拼成 `busy` 布尔量，再各自决定记哪个指标、回什么状态码——
/// "什么算忙、什么算死"这条策略因此散在两个模块里。
///
/// **调用方拿它做什么**：只映射成对外的文案与指标标签（`busy`/`dead`、`slow`/`silent`、
/// `backpressure`/`broken`）以及状态码。那些是外部契约，留在原处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// 只是一时受阻（忙 / 慢 / 背压）：**不计 strike、不摘除**，调用方按容量或超时回应。
    Transient,
    /// 判定为**死**：已计一次 strike（连续达到阈值时，条目已被移出路由并安排关闭）。
    Fatal,
}

/// 选路规则（**纯函数**，评估 §8 的 passB 建议）：从当前条目里挑出**按优先级排好序**的候选。
///
/// 次序：新鲜 → 不在 `exclude` 里 → 能服务该模型 → 精确声明优先于 `*` 通配 → 负载轻优先
/// → 心跳新者优先。两个错误变体各代表"被哪一层滤空"（`NoAgent` = 没人可用/都过期，
/// `NoModel` = 有人但都不声明这个模型），调用方据此区分 503 文案。
///
/// 为什么抽成纯函数：规则以前与"占位 + 返回槽位"的副作用揉在 `try_acquire_excluding` 里，
/// 只能靠注册表端到端测；现在规则本身可以直接用一组条目断言（见单测
/// `pick_orders_exact_over_wildcard_then_lightest`）。
#[cfg(test)]
pub(super) fn pick<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    now: u64,
    stale_after: Duration,
    model: &str,
    exclude: &[usize],
) -> Result<Vec<&'a Entry>, AcquireError> {
    pick_for_tenant(entries, now, stale_after, DEFAULT_TENANT_ID, model, exclude)
}

/// 同 [`pick`]，但只允许指定 tenant 的条目。路由隔离的唯一入口。
pub(super) fn pick_for_tenant<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    now: u64,
    stale_after: Duration,
    tenant_id: &str,
    model: &str,
    exclude: &[usize],
) -> Result<Vec<&'a Entry>, AcquireError> {
    let mut candidates: Vec<&Entry> = entries
        .filter(|e| {
            e.tenant_id == tenant_id
                && is_fresh(e.last_seen_millis.load(Ordering::Relaxed), now, stale_after)
        })
        .collect();
    if candidates.is_empty() {
        return Err(AcquireError::NoAgent);
    }
    // 在排除之前记下"是否有新鲜候选能服务该模型"。排除之后如果模型候选为空，这个事实
    // 决定它是"忙"（AllExcluded → 429）还是"根本没有这个模型"（NoModel → 404）。
    // 只看 fresh 候选：过期 agent 不构成容量证据。
    let has_model_candidate = candidates
        .iter()
        .any(|e| e.models.iter().any(|m| m == "*" || m == model));
    // 排除要**放在"有没有候选"之后**（复扫 B1）：`exclude` 是**调用方自己**传进来的（本轮
    // 已经试过的连接），把它和"注册表里没人 / 全 stale"混成同一个 `NoAgent`，会让单 agent
    // 场景下的"忙"最终报成 503 `no edge available` + `all-candidates-stale`——两处都与事实
    // 相反（注册表里有人、心跳也新鲜，只是它已经顶到承载上限）。
    candidates.retain(|e| !exclude.contains(&e.stable_id));
    if candidates.is_empty() {
        return Err(empty_reason(has_model_candidate));
    }
    // 模型过滤：只保留能服务请求模型的 agent（声明含 "*" 或含 model）
    candidates.retain(|e| e.models.iter().any(|m| m == "*" || m == model));
    if candidates.is_empty() {
        return Err(empty_reason(has_model_candidate));
    }
    // 排序：精确声明（exact=true）排前 → 负载轻优先 → 心跳新者优先。
    // bool 排序 false < true，故用 !exact 让精确者排前。
    candidates.sort_by_key(|e| {
        let exact = e.models.iter().any(|m| m == model);
        (
            !exact,
            e.inflight.load(Ordering::Relaxed),
            std::cmp::Reverse(e.last_seen_millis.load(Ordering::Relaxed)),
        )
    });
    Ok(candidates)
}

/// 候选被滤空时的错误：有模型候选被排除 ⇒ 忙；没有模型候选 ⇒ 404。
fn empty_reason(has_model_candidate: bool) -> AcquireError {
    if has_model_candidate {
        AcquireError::AllExcluded
    } else {
        AcquireError::NoModel
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// 没有任何健康 agent。
    NoAgent,
    /// 有健康 agent，但没有任何一个能服务请求的模型。
    NoModel,
    /// agent 并发已满。
    AtCapacity,
    /// 有健康、能服务该模型的候选，但它们**全部**落在调用方给出的 `exclude` 里。
    ///
    /// 与 [`Self::NoAgent`] 分开（复扫 B1）：这个错误码的含义是"重试已经把候选试过一遍了"，
    /// 而不是"没人可用"。调用方据此才能把"忙"如实报成 429 容量不足，而不是
    /// 503 `no edge available`。
    AllExcluded,
}
