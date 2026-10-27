// 总览：把网关、edge 与模型路由画成一张实时拓扑，再给出关键信号。

import { formatBytes, formatDuration } from "../api/metrics";
import { BarList, ChartPending, Sparkline } from "../components/charts";
import { Icon } from "../components/icons";
import { Badge, EmptyState, MetricCard, PageHeader, Panel, PanelHead } from "../components/ui";
import { useMetricsHistory } from "../hooks/useMetricsHistory";

export default function Overview() {
  const { latest, history } = useMetricsHistory();

  const active = history.map((h) => h.active_requests);
  const agents = history.map((h) => h.agents);
  const avgMs =
    latest && latest.request_count > 0 ? latest.request_duration_ms / latest.request_count : 0;
  const statusItems = latest
    ? Object.entries(latest.requests_by_status)
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([code, value]) => ({ label: code, value }))
    : [];

  return (
    <div className="space-y-6">
      <PageHeader
        index="01"
        eyebrow="OBSERVE / NETWORK"
        title="网络总览"
        description="公网入口、QUIC 隧道与本地模型链路在一个视图里。所有数字来自网关 /metrics，每 5 秒刷新。"
        actions={
          <>
            <Badge tone={latest && latest.agents_healthy > 0 ? "ok" : "warn"}>
              <span
                className={`status-dot ${
                  latest && latest.agents_healthy > 0 ? "status-dot-live" : "status-dot-warn"
                }`}
              />
              {latest && latest.agents_healthy > 0 ? "MESH ACTIVE" : "WAITING FOR EDGE"}
            </Badge>
            <Badge>
              <Icon name="pulse" size={11} />
              5S SAMPLE
            </Badge>
          </>
        }
      />

      <Panel>
        <PanelHead
          eyebrow="LIVE PATH"
          title="请求路径"
          description="客户端只看到 OpenAI 兼容入口；网关把请求路由到同一 tenant 的健康 edge。"
          right={
            <span className="font-mono text-[10px] text-mist-dim">
              {latest ? `${history.length} / 60 SAMPLES` : "AWAITING TELEMETRY"}
            </span>
          }
        />
        <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_228px]">
          <div className="panel-body">
            <div className="topology">
              <div className="topology-node">
                <div className="micro-label">CLIENTS</div>
                <div className="mt-3 text-sm font-medium text-paper">OpenAI SDK</div>
                <div className="mt-1 font-mono text-[10px] leading-relaxed text-mist-dim">
                  Bearer key
                  <br />
                  GET /v1/models
                </div>
              </div>
              <div className="topology-link" aria-hidden />
              <div className="topology-node topology-core">
                <div className="flex items-center justify-between gap-2">
                  <div className="micro-label text-cyan">GATEWAY</div>
                  <span className="status-dot status-dot-live" />
                </div>
                <div className="mt-3 flex items-baseline gap-1.5">
                  <span className="font-mono text-2xl leading-none text-paper">
                    {latest ? latest.active_requests : "—"}
                  </span>
                  <span className="text-[10px] text-mist">in flight</span>
                </div>
                <div className="mt-2 font-mono text-[10px] text-mist-dim">QUIC / mTLS</div>
              </div>
              <div className="topology-link" aria-hidden />
              <div className="topology-node">
                <div className="flex items-center justify-between gap-2">
                  <div className="micro-label">EDGE FLEET</div>
                  <span
                    className={`status-dot ${
                      latest && latest.agents_healthy > 0 ? "status-dot-live" : "status-dot-warn"
                    }`}
                  />
                </div>
                <div className="mt-3 flex items-baseline gap-1.5">
                  <span className="font-mono text-2xl leading-none text-paper">
                    {latest ? `${latest.agents_healthy} / ${latest.agents}` : "— / —"}
                  </span>
                  <span className="text-[10px] text-mist">healthy / registered</span>
                </div>
                <div className="mt-2 font-mono text-[10px] text-mist-dim">
                  private network · outbound dial
                </div>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line-soft pt-4">
              <span className="font-mono text-[9px] tracking-[0.14em] text-mist-dim">ROUTE</span>
              <span className="flex items-center gap-2 text-[11px] text-mist">
                <Icon name="arrow" size={12} className="text-signal" />
                edge-local model
              </span>
              <span className="font-mono text-[10px] text-mist-dim">/v1/chat/completions</span>
              <span className="ml-auto font-mono text-[10px] text-mist-dim">SSE STREAM</span>
            </div>
          </div>

          <aside className="border-t border-line-soft px-5 py-5 lg:border-l lg:border-t-0">
            <div className="eyebrow-muted">SIGNAL SUMMARY</div>
            <dl className="mt-4 space-y-3.5">
              {[
                [
                  "ROUTABLE EDGES",
                  latest ? `${latest.agents_healthy} / ${latest.agents}` : "— / —",
                  "signal",
                ],
                ["REGISTERED", latest ? String(latest.agents) : "—", "paper"],
                ["ACTIVE REQUESTS", latest ? String(latest.active_requests) : "—", "paper"],
                ["AVG LATENCY", latest ? formatDuration(avgMs) : "—", "cyan"],
              ].map(([label, value, tone]) => (
                <div key={label} className="flex items-baseline justify-between gap-3">
                  <dt className="micro-label leading-relaxed">{label}</dt>
                  <dd
                    className={`font-mono text-sm tabular-nums ${
                      tone === "signal"
                        ? "text-signal"
                        : tone === "cyan"
                          ? "text-cyan"
                          : "text-paper"
                    }`}
                  >
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
            <div className="mt-5 border-t border-line-soft pt-4 text-[10px] leading-relaxed text-mist-dim">
              注册数包含心跳过期节点；只有 ROUTABLE EDGES 会接收新请求。
            </div>
          </aside>
        </div>
      </Panel>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="在线 Agents"
          value={latest ? latest.agents_healthy : "—"}
          hint={latest ? `可路由；已注册 ${latest.agents}（含心跳过期）` : "可路由"}
          tone={latest && latest.agents_healthy > 0 ? "ok" : "warn"}
        >
          <Sparkline data={agents} height={34} stroke="#b9f27b" />
        </MetricCard>
        <MetricCard
          label="在途请求"
          value={latest ? latest.active_requests : "—"}
          hint="当前并发转发中"
          tone="cyan"
        >
          <Sparkline data={active} height={34} stroke="#79d7d1" />
        </MetricCard>
        <MetricCard
          label="累计请求"
          value={latest ? latest.request_count.toLocaleString() : "—"}
          hint={
            latest && latest.request_count > 0 ? `平均耗时 ${formatDuration(avgMs)}` : undefined
          }
        >
          <div className="flex items-center gap-2 font-mono text-[10px] text-mist-dim">
            <Icon name="pulse" size={11} />
            counter / since start
          </div>
        </MetricCard>
        <MetricCard
          label="累计转发"
          value={latest ? formatBytes(latest.bytes_out) : "—"}
          hint="回传给客户端的字节"
        >
          <div className="flex items-center gap-2 font-mono text-[10px] text-mist-dim">
            <Icon name="arrow" size={11} />
            edge → client
          </div>
        </MetricCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHead
            title="在途请求趋势"
            description="最近 60 个采样点（5s 间隔）"
            right={<span className="font-mono text-[10px] text-mist-dim">{active.length} PTS</span>}
          />
          <div className="panel-body pt-4">
            {active.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={active} height={96} stroke="#79d7d1" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHead
            title="在线 Agent 数趋势"
            description="可路由 edge 数（不含心跳过期）"
            right={<span className="font-mono text-[10px] text-mist-dim">{agents.length} PTS</span>}
          />
          <div className="panel-body pt-4">
            {agents.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={agents} height={96} stroke="#b9f27b" />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.25fr_1fr]">
        <Panel>
          <PanelHead
            title="状态码分布（累计）"
            description="按 HTTP 状态码的请求计数"
            right={<Badge tone="cyan">HTTP</Badge>}
          />
          <div className="panel-body">
            {statusItems.length > 0 ? (
              <BarList items={statusItems} />
            ) : (
              <EmptyState title="暂无请求记录" detail="客户端第一次请求后，状态码会出现在这里。" />
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHead title="运行约束" description="这张视图能解释的边界" />
          <div className="panel-body space-y-3">
            {[
              ["PUBLIC EDGE", "/v1/* · OpenAI compatible"],
              ["AUTH", "Bearer key · tenant scoped"],
              ["TRANSPORT", "QUIC + mTLS · agent dial-out"],
              ["RETRY", "tunnel open/write only · never 504"],
            ].map(([label, value]) => (
              <div
                key={label}
                className="flex items-start justify-between gap-4 border-b border-line-soft pb-3 last:border-0 last:pb-0"
              >
                <span className="font-mono text-[9px] tracking-[0.1em] text-mist-dim">{label}</span>
                <span className="text-right font-mono text-[10px] leading-relaxed text-mist">
                  {value}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
