//! metrics 的单元测试：从 `metrics.rs` 的内联 `mod tests` 原样搬出。
//!
//! `tests` 仍是 `metrics` 的子模块，所以 `use super::*` 仍能看到 `MetricsInner` 的私有字段
//! （中毒测试要直接锁 `inner.status_counts`）。

use super::{AdmissionDomain, Metrics};

/// Phase 0 表征测试：**`/metrics` 文本的完整字节固定**。
///
/// 为什么需要它：Prometheus 文本的 HELP/TYPE 与样本**必须紧贴**，且 `hlmg_*` 名字/label
/// 是对外契约（前端解析、告警规则都依赖）。后续要把 `render()` 里 7 段重复的 family 渲染
/// 收敛成一个 helper——没有这份 golden，"收敛"很容易顺手改掉顺序、HELP 文案或空 family 的
/// 跳过条件，而现有测试只检查"名字出现过"。
///
/// 这份期望值是**当前实现实测输出**，不是手算的；改线格式/指标契约时必须同步更新
/// `metrics.golden` 并在 PR 里说明兼容性影响。
#[test]
fn the_prometheus_text_is_byte_for_byte_stable() {
    let m = Metrics::default();
    m.record_status(200);
    m.record_status(500);
    m.record_agent_rejection("registry-empty");
    m.record_agent_rejection("all-candidates-stale");
    m.record_tunnel_retry("ok");
    m.record_forward_end("upstream_end");
    m.record_client_stall("request-body");
    m.record_head_timeout("slow");
    m.record_tunnel_open_timeout("busy");
    m.record_tunnel_write_failure("backpressure");
    m.record_accept_error();
    m.add_bytes_out(7);
    m.record_aborted();
    // 守卫要活到渲染结束：Drop 会把 gauge 置回 0。
    let _accepting = m.mark_accepting();
    let _conn = m.mark_agent_connected();

    assert_eq!(
        m.render(2, 1, 3, 4),
        include_str!("metrics.golden"),
        "Prometheus 文本变了：HELP/TYPE 顺序、空 family 跳过条件、label 或样本顺序被改动"
    );
}

/// 规格（评估 §7 步骤 6 的结转项 A / `PROJECT_SCAN` P2-12）：**计数锁中毒后
/// `/metrics` 不能跟着挂**。
///
/// 这些映射只被"加一"与"渲染"访问，守卫内 panic 不会写坏它们；而 `.lock().unwrap()`
/// 会把一次 panic 放大成"`/metrics` 永久 500"——恰恰是排障时最需要它的时刻。
#[test]
fn a_poisoned_counter_lock_does_not_take_metrics_down() {
    let m = Metrics::default();
    m.record_status(200);

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = m.inner.status_counts.lock().unwrap();
        panic!("poison status_counts");
    }));
    assert!(poisoned.is_err(), "前提：panic 发生了");
    assert!(m.inner.status_counts.is_poisoned(), "前提：锁中毒了");

    // 写路径与渲染路径都必须照常
    m.record_status(204);
    let text = m.render(0, 0, 0, 0);
    assert!(
        text.contains("hlmg_requests_total{status=\"200\"} 1"),
        "渲染必须带上中毒前的计数：\n{text}"
    );
    assert!(
        text.contains("hlmg_requests_total{status=\"204\"} 1"),
        "中毒后新记的状态码也要出现：\n{text}"
    );
}

/// 规格（记录 R8）：**占位不得制造"幽灵占位"**——`active_count()` 永远不超过已发出的票数。
///
/// 旧实现（`fetch_add` 后超限回滚）在回滚前那一瞬间把计数抬高 1；若持票者恰在那一刻释放，
/// 紧接着到达的请求会读到 `prev >= limit` 而被拒，而闸门其实是空的。这条用一个**采样线程**
/// 盯住计数上界：M 个线程在 barrier 上对齐、同时抢同一个槽位，采样到 `active > limit` 即红。
#[test]
fn try_enter_never_inflates_the_counter_above_the_limit() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    };

    for round in 0..50 {
        let metrics = Metrics::default();
        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let stop = Arc::new(AtomicBool::new(false));

        let sampler = {
            let (m, b, stop) = (metrics.clone(), barrier.clone(), stop.clone());
            std::thread::spawn(move || {
                b.wait();
                let (mut worst, mut worst_gated) = (0u64, 0u64);
                while !stop.load(Ordering::Relaxed) {
                    worst = worst.max(m.active_count());
                    worst_gated = worst_gated.max(m.active_gated_count());
                }
                (worst, worst_gated)
            })
        };
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                let (m, b) = (metrics.clone(), barrier.clone());
                std::thread::spawn(move || {
                    b.wait();
                    // 抢到就立刻放：制造"持票者释放"与"别人正在占位"重叠的窗口
                    if let Some(ticket) = m.try_enter(1, AdmissionDomain::Gated) {
                        drop(ticket);
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        let (worst, worst_gated) = sampler.join().unwrap();
        assert!(
            worst <= 1 && worst_gated <= 1,
            "第 {round} 轮采样到 active={worst} / gated={worst_gated} > limit=1：                 存在幽灵占位 ⇒ 会误拒（R8）"
        );
    }
}

/// 规格（R8 的另一半）：**占位/释放的记账必须精确**，`0` 仍然是"不限"。
#[test]
fn try_enter_accounts_exactly_and_treats_zero_as_unlimited() {
    let m = Metrics::default();
    let a = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("第 1 个应当放行");
    let b = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("第 2 个应当放行");
    assert!(
        m.try_enter(2, AdmissionDomain::Gated).is_none(),
        "第 3 个必须被拒"
    );
    assert_eq!(
        m.active_count(),
        2,
        "被拒的那次不得留下任何计数（否则会连锁误拒）"
    );

    drop(a);
    assert_eq!(m.active_count(), 1);
    let c = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("释放一个之后必须能再进");
    assert_eq!(m.active_count(), 2);
    drop((b, c));
    assert_eq!(m.active_count(), 0);

    // `0` = 不限：一直放行，但仍然计数
    let m2 = Metrics::default();
    let t1 = m2
        .try_enter(0, AdmissionDomain::Gated)
        .expect("limit=0 无条件放行");
    let t2 = m2
        .try_enter(0, AdmissionDomain::Gated)
        .expect("limit=0 无条件放行");
    assert_eq!(m2.active_count(), 2);
    drop(t1);
    assert_eq!(m2.active_count(), 1);
    drop(t2);
    assert_eq!(m2.active_count(), 0);
}

/// 规格（复扫 A3）：**探针域的票据不得消耗受限域的预算**。
///
/// `/healthz` 是**无认证**的豁免路径（鉴权只包控制面命名空间），先前用 `limit = 0` 表达"不能被拒"。
/// 但它照样领票、照样加 `active`，而 `/v1/*` 判的是**同一个** `active` ⇒ 对着 `/healthz` 打
/// 一轮就能把 `/v1` 顶到 429，而 LB 看到探针仍 200、认为实例健康：探针把闸门占满了，对外
/// 却表现为"整机正常、谁都调不通"。
///
/// 域把"能不能被拒"与"记在谁的账上"分开。这条同时钉住三件事：①探针在途不影响受限余量；
/// ②探针域有自己的上限；③**总数**仍统计全部在途（`hlmg_active_requests` 与 `drain()` 的
/// 语义不变）。
#[test]
fn a_probe_ticket_does_not_consume_the_gated_budget() {
    let m = Metrics::default();
    let g1 = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("第 1 个受限请求");
    let g2 = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("第 2 个受限请求");
    assert!(
        m.try_enter(2, AdmissionDomain::Gated).is_none(),
        "前提：受限域已满"
    );

    // 探针域有**自己**的预算（这里用 2 演示；生产取值见 `MAX_CONCURRENT_PROBES`）。
    let p1 = m
        .try_enter(2, AdmissionDomain::Probe)
        .expect("探针有自己的预算");
    let p2 = m
        .try_enter(2, AdmissionDomain::Probe)
        .expect("探针有自己的预算");
    assert_eq!(
        m.active_gated_count(),
        2,
        "探针在途不得推动受限计数（修复前这里是 4）"
    );
    assert_eq!(
        m.active_count(),
        4,
        "总数仍统计全部在途：指标与 drain 的语义不变"
    );

    // ① 受限域释放一个 → 立刻能再进，哪怕探针还在途
    drop(g1);
    let g3 = m
        .try_enter(2, AdmissionDomain::Gated)
        .expect("探针在途不该占受限余量（修复前这里是 None）");

    // ② 探针域自己的上限独立生效
    assert!(
        m.try_enter(2, AdmissionDomain::Probe).is_none(),
        "探针预算满了也要拒（无认证路径不能无界消耗）"
    );
    assert_eq!(m.active_probe_count(), 2);

    // ③ 借与还都必须精确回到 0
    drop((g2, g3, p1, p2));
    assert_eq!(
        (
            m.active_count(),
            m.active_gated_count(),
            m.active_probe_count()
        ),
        (0, 0, 0),
        "票据 Drop 必须把三个计数都还干净"
    );
}

/// 规格（复扫 A8）：**抓取票只占抓取域的额度，完全不算一次请求**。
///
/// `/metrics` 不走 id / 访问日志 / 状态码那条链（`request_id_middleware` 对它直接放行），而
/// 恒等式 `request_count − Σ状态码 − aborted == 0` 依赖"记了状态码才算一次请求"。所以抓取票
/// 必须与 `try_enter` 分开：它只加抓取域的计数，`request_count` / `active` / 耗时一个都不动
/// ——否则每次抓取都让恒等式 +1，真正的槽位泄漏会被淹没。
#[test]
fn a_scrape_ticket_bounds_scrapes_without_counting_them_as_requests() {
    let m = Metrics::default();
    let before = m.identity_terms();

    let s1 = m
        .try_enter_uncounted(2, AdmissionDomain::Scrape)
        .expect("抓取有自己的预算");
    let s2 = m
        .try_enter_uncounted(2, AdmissionDomain::Scrape)
        .expect("抓取有自己的预算");
    assert_eq!(m.active_scrape_count(), 2);
    assert!(
        m.try_enter_uncounted(2, AdmissionDomain::Scrape).is_none(),
        "抓取预算满了要拒（这条无认证路径此前完全无界）"
    );
    assert_eq!(
        m.identity_terms(),
        before,
        "抓取不得动 request_count（否则恒等式每次抓取漂移 +1）"
    );
    assert_eq!(
        m.active_count(),
        0,
        "抓取也不该出现在 hlmg_active_requests / drain 的读数里"
    );
    assert_eq!(
        (m.active_gated_count(), m.active_probe_count()),
        (0, 0),
        "抓取票不得推动另外两个域的计数"
    );

    drop((s1, s2));
    assert_eq!(m.active_scrape_count(), 0, "票据 Drop 要把抓取计数还干净");
    assert_eq!(m.identity_terms(), before, "归还路径同样不得动请求账本");
}

/// 规格（复扫 C2-5）：这一族的三种标签是**三件不同的事**，HELP 不能把它们统称"重试"。    ///
/// 文案是给人看的，但它决定告警怎么写：把 `no-alternative` 当成重试次数，会从"重试很多"
/// 得出"上游不稳"的错误结论——而它实际的含义是"**没有别的 agent 可换**"。
#[test]
fn tunnel_retry_help_does_not_call_every_outcome_a_retry() {
    let m = Metrics::default();
    for outcome in ["ok", "failed", "no-alternative"] {
        m.record_tunnel_retry(outcome);
    }
    let text = m.render(0, 0, 0, 0);
    for outcome in ["ok", "failed", "no-alternative"] {
        assert!(
            text.contains(&format!(
                "hlmg_tunnel_retries_total{{outcome=\"{outcome}\"}} 1"
            )),
            "{outcome} 应当各自成一条样本：\n{text}"
        );
    }
    let help = text
        .lines()
        .find(|l| l.starts_with("# HELP hlmg_tunnel_retries_total"))
        .expect("HELP 必须在");
    assert!(
        !help.contains("Requests retried"),
        "整族不是 'Requests retried'（`no-alternative` 不是重试）：{help}"
    );
    assert!(
        help.contains("no-alternative"),
        "HELP 要点名那个例外：{help}"
    );
}

/// 规格（P2-11）：**连接任务的 panic 必须把 `hlmg_quic_connections` 降回去**。
///
/// 旧的"先 +1、末尾 -1"写法在这条测试下必然红：panic 展开时末尾那句不执行，gauge 永久虚高，
/// 而没有任何东西会去纠正它（注册表条目同样漏掉，见 `registry::Registration`）。
#[test]
fn the_connection_gauge_is_released_even_when_the_task_panics() {
    let m = Metrics::default();
    assert_eq!(m.quic_connections(), 0);

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = m.mark_agent_connected();
        assert_eq!(m.quic_connections(), 1, "在连时应为 1");
        panic!("connection task blew up");
    }));
    assert!(panicked.is_err(), "前提：panic 发生了");
    assert_eq!(
        m.quic_connections(),
        0,
        "panic 展开也必须归还 gauge（否则永久虚高，只能重启）"
    );
    assert!(
        m.render(0, 0, 0, 0)
            .contains("hlmg_agent_connections_total 1"),
        "累计连接数是 counter，不因 panic 回退"
    );
}

/// 规格（P2-11）：递减**饱和**——0 上再减不许回绕成 `u64::MAX`。
#[test]
fn the_connection_gauge_never_wraps_around() {
    let m = Metrics::default();
    m.agent_disconnected();
    m.agent_disconnected();
    assert_eq!(
        m.quic_connections(),
        0,
        "裸 fetch_sub 会回绕成 u64::MAX，仪表盘彻底不可读"
    );
}

/// 规格：渲染出的每个 `# HELP` 后面必须**紧跟同名的 `# TYPE`**。
///
/// 这不是格式洁癖：Prometheus 的文本解析按"家族"分组，HELP 与 TYPE 之间插进另一个家族的
/// 样本会让解析失败（整轮抓取报废）。本仓库真踩过这个坑——加 `hlmg_requests_aborted_total`
/// 时把 HELP 插到了 `hlmg_request_count` 的 HELP 与 TYPE 之间。这条把它变成机器判据，
/// 顺带保证新指标（`hlmg_http_accept_errors_total`）确实被渲染出来。
/// 规格（记录 P2-14）：**转发退出原因要真的渲染出来**，且 HELP/TYPE 成对、空家族不输出。
#[test]
fn forward_end_kinds_are_rendered_with_their_own_type_line() {
    let m = Metrics::default();
    assert!(
        !m.render(0, 0, 0, 0).contains("hlmg_forward_ends_total"),
        "没有记录过就不该输出这个家族（避免 HELP 后面没有样本）"
    );

    m.record_forward_end("upstream_closed");
    m.record_forward_end("upstream_closed");
    m.record_forward_end("idle_timeout");
    let text = m.render(0, 0, 0, 0);
    assert!(
        text.contains("# HELP hlmg_forward_ends_total "),
        "要有 HELP：\n{text}"
    );
    assert!(
        text.contains("# TYPE hlmg_forward_ends_total counter"),
        "要有 TYPE：\n{text}"
    );
    assert!(
        text.contains("hlmg_forward_ends_total{kind=\"upstream_closed\"} 2"),
        "计数要准：\n{text}"
    );
    assert!(
        text.contains("hlmg_forward_ends_total{kind=\"idle_timeout\"} 1"),
        "kind 要各算各的：\n{text}"
    );
}

#[test]
fn every_help_line_is_immediately_followed_by_its_own_type_line() {
    let text = Metrics::default().render(0, 0, 0, 0);
    let lines: Vec<&str> = text.lines().collect();
    let mut checked = 0;
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = line.strip_prefix("# HELP ") else {
            continue;
        };
        let name = name.split_whitespace().next().expect("HELP 必须带指标名");
        let next = lines.get(i + 1).unwrap_or(&"");
        assert!(
            next.starts_with(&format!("# TYPE {name} ")),
            "`{name}` 的 HELP 后面必须紧跟同名的 TYPE（家族不能交错），实际下一行是 `{next}`"
        );
        checked += 1;
    }
    assert!(checked > 10, "应当检查到足够多的家族（实际 {checked}）");
    assert!(
        text.contains("# TYPE hlmg_http_accept_errors_total counter"),
        "新指标必须被渲染：\n{text}"
    );
}
