//! HTTP 准入的域与票据：`AdmissionDomain`、`try_enter*`、`Admission`、`AcceptingGuard`。
//!
//! 与计数器分家的理由：这里回答"谁能进、进来记在谁的账上"，而 `Metrics` 的其余部分回答
//! "发生了什么"。`Admission::drop` 要写 `MetricsInner` 的原子量，所以本模块是 `metrics`
//! 子树的一员——不需要把 `inner` 提成 `pub`。
//!
//! 三个域（Gated/Probe/Scrape）互不相欠：`/healthz` 被 429 会让 LB 摘掉健康实例，
//! `/v1` 被 429 就是全量失败；抓取域的票据还**不算一次请求**。

use std::{sync::atomic::Ordering, time::Instant};

use super::Metrics;

/// 准入域（复扫 A3）：**豁免路径不得消耗受限路径的预算**。
///
/// 为什么需要"域"这个概念：先前用 `limit == 0` 表达"豁免"（`/healthz`），而 `0` 的语义只是
/// "不判上限"——领票、计数一样不少，加的还恰好是**受限路径用来比较的同一个计数器**。于是豁免
/// 路径实际在花受限预算：对着无认证的 `/healthz` 打一轮就能把 `/v1` 顶到 429，而 LB 因为探针
/// 仍返回 200 而认为实例健康（"整机正常、谁都调不通"）。
///
/// 域把"能不能被拒"与"记在谁的账上"分开：每个域有自己的在途计数与自己的上限，互不干扰；
/// **总数**（[`Metrics::active_count`]）仍然统计全部在途票，所以 `hlmg_active_requests` 与
/// `drain()` 的语义一个都没变。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDomain {
    /// 受 `max_concurrent_requests` 约束的常规路径（`/v1/*`、UI、admin…）。
    Gated,
    /// 探针（`/healthz`）：自己不占受限额度，但有一个**独立的、宽松的**上限，免得这条无认证
    /// 路径被洪水无界消耗（取值与理由见 `http::admission::MAX_CONCURRENT_PROBES`）。
    Probe,
    /// 指标抓取（`/metrics`）：与探针域同理，但计数**完全独立**（复扫 A8）。
    ///
    /// 三个域各自一个计数器，不是"省一个字段"的问题：只要两条路径共用一个域，其中一条的洪水
    /// 就能把另一条顶成 429——`/healthz` 被 429 会让 LB 摘掉健康实例，`/v1` 被 429 就是全量
    /// 失败。抓取域的票据还**不算一次请求**（见 [`Metrics::try_enter_uncounted`]）。
    Scrape,
}

impl Metrics {
    /// 标记「隧道入口正在接受连接」；返回的守卫 Drop 时置回 0。
    ///
    /// 用 Drop 而不是「循环之后的语句」，是因为任务被 abort（优雅关闭）或 panic 时
    /// 循环后的代码不会执行——本仓库已经在同一个坑里摔过两次（`Admission` 的槽位释放、
    /// `serve_https` 的配置解析），手法保持一致。
    pub fn mark_accepting(&self) -> AcceptingGuard {
        self.inner.quic_accepting.store(1, Ordering::Relaxed);
        AcceptingGuard(self.clone())
    }

    /// 原子占位（HTTP 全局并发 admission）：**CAS 循环**，超限直接返回 `None`（调用方 429）；
    /// 通过 → 返回 [`Admission`] 票据，**槽位由票据的 Drop 释放**（见其文档）。
    ///
    /// 为什么是 CAS 而不是 `fetch_add` + 超限回滚（记录 R8）：后者在"加了但还没回滚"的那一瞬间
    /// 让计数**比真实持票数多 1**（幽灵占位）。若恰好有持票者在这一刻释放，紧接着到达的请求会
    /// 读到 `prev >= limit` 而被拒——**闸门其实是空的**（"双双误拒"，客户端拿到本不该有的 429）。
    /// CAS 只在"确实要到票"时才加计数，因此
    /// `active_count()` **恒等于**已发出的票数（顺带让 `hlmg_active_requests` 不再有瞬时尖峰，
    /// 排空判据 `drain()` 读的也是它）。
    ///
    /// `limit == 0` = **本域不限**：直接占位（仍然计数，票据照常负责 `request_count` 与时长记账）。
    ///
    /// `domain` 决定这笔在途记进哪个域（见 [`AdmissionDomain`]）：受限路径只与受限域的计数比较，
    /// 所以豁免路径在途多少都不会减少别人能用的额度。
    pub fn try_enter(&self, limit: u32, domain: AdmissionDomain) -> Option<Admission> {
        self.enter(limit, domain, true)
    }

    /// 同 [`Metrics::try_enter`]，但票据**不算一次请求**：不进 `request_count`、不进
    /// `active`（`hlmg_active_requests` 与 `drain()`）、也不记耗时（复扫 A8）。
    ///
    /// 给 `/metrics` 抓取用。它必须与 `try_enter` 分开，因为"配额"与"记账"是两件事：
    /// `/metrics` 不走 id / 访问日志 / 状态码那条链（`request_id_middleware` 对它直接放行），
    /// 而仓库自用的恒等式 `request_count − Σ状态码 − aborted == 0` 依赖"记了状态码才算一次
    /// 请求"——在这里也 `request_count += 1`，恒等式就会被**每次抓取**各漂移 +1，把真正的槽位
    /// 泄漏淹没。它占的只有 [`AdmissionDomain::Scrape`] 的在途计数（于是抓取洪水有界）。
    pub fn try_enter_uncounted(&self, limit: u32, domain: AdmissionDomain) -> Option<Admission> {
        self.enter(limit, domain, false)
    }

    fn enter(&self, limit: u32, domain: AdmissionDomain, counted: bool) -> Option<Admission> {
        let domain_counter = match domain {
            AdmissionDomain::Gated => &self.inner.active_gated,
            AdmissionDomain::Probe => &self.inner.active_probe,
            AdmissionDomain::Scrape => &self.inner.active_scrape,
        };
        if limit > 0 {
            let limit = u64::from(limit);
            let mut current = domain_counter.load(Ordering::Relaxed);
            loop {
                if current >= limit {
                    return None;
                }
                match domain_counter.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    // 别的线程改了计数：用观测到的新值重试（不重试就真的会漏放行）
                    Err(observed) => current = observed,
                }
            }
        } else {
            domain_counter.fetch_add(1, Ordering::Relaxed);
        }
        // 总数（`hlmg_active_requests` 与 `drain()` 读它）：**只在本域确实占到票之后**才加，
        // 所以它仍然恒等于已发出的票数、不会留下幽灵占位（R8）。抓取票（`counted = false`）
        // 刻意不在这里出现——见 `try_enter_uncounted`。
        if counted {
            self.inner.active.fetch_add(1, Ordering::Relaxed);
            self.inner.request_count.fetch_add(1, Ordering::Relaxed);
        }
        Some(Admission {
            metrics: self.clone(),
            start: Instant::now(),
            domain,
            counted,
        })
    }
}

/// 在途准入票据：持有期间该请求计入 `hlmg_active_requests`；**槽位在 Drop 时释放**。
///
/// 释放必须挂在 Drop 上，不能依赖调用方"await 之后"的尾部语句：客户端中断时 hyper 会
/// 直接 drop 在途的请求 future，尾部代码永不执行——槽位会永久泄漏，配了
/// `max_concurrent_requests` 的网关会被**一次**中断打成此后全部 429（只能重启）。
///
/// 因此：票据要么被正常作用域 drop，要么随请求 future 被丢弃而 drop，两条路都归还槽位。
/// 注意不可 `Clone`/`Copy`（会导致重复释放）。
///
/// 票据记着自己是哪个域的（复扫 A3），否则 Drop 不知道该把票还给受限域还是探针域；
/// 还记着它**算不算一次请求**（复扫 A8，见 [`Metrics::try_enter_uncounted`]）。
pub struct Admission {
    metrics: Metrics,
    start: Instant,
    domain: AdmissionDomain,
    /// `false` = 只占域额度、不进 `request_count` / `active` / 耗时（`/metrics` 抓取票）。
    counted: bool,
}

impl Drop for Admission {
    fn drop(&mut self) {
        match self.domain {
            AdmissionDomain::Gated => &self.metrics.inner.active_gated,
            AdmissionDomain::Probe => &self.metrics.inner.active_probe,
            AdmissionDomain::Scrape => &self.metrics.inner.active_scrape,
        }
        .fetch_sub(1, Ordering::Relaxed);
        if !self.counted {
            return;
        }
        self.metrics.inner.active.fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .inner
            .total_duration_ms
            .fetch_add(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

/// 隧道入口「接受中」守卫：见 [`Metrics::mark_accepting`]。Drop 时把 gauge 置回 0，
/// 因此**结束方式不影响可观测性**——正常返回、任务被 abort、panic 都会留下痕迹。
pub struct AcceptingGuard(Metrics);

impl Drop for AcceptingGuard {
    fn drop(&mut self) {
        self.0.inner.quic_accepting.store(0, Ordering::Relaxed);
    }
}
