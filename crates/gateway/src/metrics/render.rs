//! Prometheus 文本渲染：名字/HELP/TYPE/label 的对外契约都在这里。
//!
//! 从 `metrics/mod.rs` 切出来的理由：计数器与准入回答"发生了什么"，本模块回答"怎么把它
//! 写成 Prometheus 能读的文本"。`render` 原先有 7 段逐字重复的"HELP/TYPE + 排序键 + 循环"，
//! 这里收敛成两个 family helper；**输出必须逐字节不变**，由 `metrics.golden` 钉住。
//!
//! `HLMG_*` 的名字、HELP 文案与样本顺序都是外部契约（前端解析、告警规则），改这里要同步改
//! `metrics.golden` 并在 PR 里说明。

use std::collections::HashMap;
use std::sync::Mutex;

use crate::sync::lock_or_recover;

use super::Metrics;

impl Metrics {
    /// 渲染为 Prometheus 文本格式。
    ///
    /// - `agent_count`：注册表条目数（含失联但连接未关的）
    /// - `agents_healthy`：其中**心跳未过期、真正可路由**的数量
    /// - `verify_hits` / `verify_misses`：已验证身份缓存的命中数与**真跑 argon2 的次数**
    ///   （来自 `Storage`；`verified_cache_max: 0` 时前者恒为 0、后者等于校验次数）
    pub fn render(
        &self,
        agent_count: usize,
        agents_healthy: usize,
        verify_hits: u64,
        verify_misses: u64,
    ) -> String {
        let inner = &self.inner;
        let mut out = String::with_capacity(512);

        push_status_family(&mut out, &inner.status_counts);
        push_gauge(
            &mut out,
            "hlmg_active_requests",
            "Currently in-flight requests.",
            inner.active.load(std::sync::atomic::Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "hlmg_agents",
            "Registered agent entries, including ones whose heartbeats have expired.",
            agent_count as u64,
        );
        push_gauge(
            &mut out,
            "hlmg_agents_healthy",
            "Registered agents whose last heartbeat is within agent_stale_secs (routable candidates).",
            agents_healthy as u64,
        );
        push_labeled_family(
            &mut out,
            "hlmg_tunnel_retries_total",
            "Tunnel-setup failures that led to an agent switch, by outcome. ok and failed count retries; \
             no-alternative counts the times there was no other agent to switch to, so it is not a retry \
             and the family sum is neither the retry count nor the failure count.",
            "outcome",
            &inner.tunnel_retries,
        );
        push_labeled_family(
            &mut out,
            "hlmg_agent_rejections_total",
            "Requests rejected because no routable agent was available, by reason.",
            "reason",
            &inner.agent_rejections,
        );
        push_labeled_family(
            &mut out,
            "hlmg_forward_ends_total",
            "Response forwarding exits by reason. Most of these happen after a 200 was already written \
             to the client (truncated body, idle timeout, upstream closed), so the access log cannot \
             show them; see ForwardEnd::label for the kinds.",
            "kind",
            &inner.forward_ends,
        );
        push_labeled_family(
            &mut out,
            "hlmg_client_stalls_total",
            "Requests abandoned because the client stopped making progress, by direction. Kept slots do \
             not leak: each one is released when the request ends.",
            "phase",
            &inner.client_stalls,
        );
        push_labeled_family(
            &mut out,
            "hlmg_upstream_head_timeouts_total",
            "Response heads that exceeded head_timeout_secs; class=slow means the agent had answered \
             recently and is merely blocked (504, not evicted), class=silent means nothing came back \
             within the window (counts toward eviction).",
            "class",
            &inner.head_timeouts,
        );
        push_labeled_family(
            &mut out,
            "hlmg_tunnel_open_timeouts_total",
            "Tunnel stream opens that exceeded tunnel_op_secs; class=busy means the agent was at capacity \
             (backpressure, not evicted), class=dead means the connection was treated as broken and evicted.",
            "class",
            &inner.tunnel_open_timeouts,
        );
        push_labeled_family(
            &mut out,
            "hlmg_tunnel_write_failures_total",
            "Request frames that could not be written to the tunnel; class=backpressure means the write \
             timed out (connection-level backpressure, not evicted), class=broken means the write returned \
             an error (connection treated as broken and evicted).",
            "class",
            &inner.tunnel_write_failures,
        );
        push_counter(
            &mut out,
            "hlmg_bytes_out",
            "Bytes forwarded to clients.",
            inner.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_request_duration_ms",
            "Total request duration in ms (sum).",
            inner
                .total_duration_ms
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_request_count",
            "Total requests (sum).",
            inner
                .request_count
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_requests_aborted_total",
            "Requests dropped before a status was written (client aborted or the connection was cut).",
            inner.aborted.load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_key_verify_hits_total",
            "Cached key verifications served without argon2.",
            verify_hits,
        );
        push_counter(
            &mut out,
            "hlmg_key_verify_misses_total",
            "Key verifications that ran argon2 (a cache miss, or the cache is disabled via verified_cache_max: 0).",
            verify_misses,
        );
        push_gauge(
            &mut out,
            "hlmg_quic_connections",
            "Currently open agent QUIC connections.",
            inner
                .quic_connections
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "hlmg_quic_accepting",
            "Whether the tunnel entry still accepts new edge connections (1/0).",
            inner
                .quic_accepting
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_http_accept_errors_total",
            "Public entry accept() failures (EMFILE, ECONNABORTED, ...); the entry keeps listening and \
             retries with backoff.",
            inner.http_accept_errors.load(std::sync::atomic::Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "hlmg_agent_connections_total",
            "Cumulative agent connections (reconnects).",
            inner
                .agent_connections_total
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        out
    }
}

/// 无 label 的单个样本（HELP/TYPE 紧贴样本）。
fn push_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    push_scalar(out, name, help, "gauge", value);
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    push_scalar(out, name, help, "counter", value);
}

fn push_scalar(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

/// `status` 家族：按状态码升序；**空表也输出 HELP/TYPE**（与旧实现一致）。
fn push_status_family(out: &mut String, counts: &Mutex<HashMap<u16, u64>>) {
    out.push_str("# HELP hlmg_requests_total Total gateway requests by HTTP status.\n");
    out.push_str("# TYPE hlmg_requests_total counter\n");
    let counts = lock_or_recover(counts);
    let mut keys: Vec<u16> = counts.keys().copied().collect();
    keys.sort_unstable();
    for code in keys {
        out.push_str(&format!(
            "hlmg_requests_total{{status=\"{code}\"}} {}\n",
            counts[&code]
        ));
    }
}

/// 有 label 的家族：**空表整族跳过**（旧实现如此），键按字典序。
fn push_labeled_family(
    out: &mut String,
    name: &str,
    help: &str,
    label: &str,
    counts: &Mutex<HashMap<&'static str, u64>>,
) {
    let counts = lock_or_recover(counts);
    if counts.is_empty() {
        return;
    }
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n"));
    let mut keys: Vec<&&str> = counts.keys().collect();
    keys.sort_unstable();
    for key in keys {
        out.push_str(&format!("{name}{{{label}=\"{key}\"}} {}\n", counts[*key]));
    }
}
