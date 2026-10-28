// 指标：把 Prometheus 采样变成可读的遥测面板，原始文本按需展开。

import { useState } from "react";

import { formatBytes, formatDuration } from "../api/metrics";
import { BarList, ChartPending, Sparkline } from "../components/charts";
import { Icon } from "../components/icons";
import {
  Badge,
  Button,
  EmptyState,
  MetricCard,
  PageHeader,
  Panel,
  PanelHead,
} from "../components/ui";
import { useMetricsHistory } from "../hooks/useMetricsHistory";

export default function MetricsPage() {
  const { latest, history, raw, error } = useMetricsHistory();
  const [showRaw, setShowRaw] = useState(false);

  const active = history.map((h) => h.active_requests);
  const bytes = history.map((h) => h.bytes_out);
  const agents = history.map((h) => h.agents);
  const counts = history.map((h) => h.request_count);

  const statusItems = latest
    ? Object.entries(latest.requests_by_status)
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([code, value]) => ({ label: code, value }))
    : [];

  return (
    <div className="space-y-6">
      <PageHeader
        index="04"
        eyebrow="OBSERVE / TELEMETRY"
        title="指标"
        description="每 5 秒轮询 /metrics，保留最近 60 个采样点。计数器和 gauge 在同一时间序列里对齐。"
        actions={
          <>
            <Badge tone="cyan">{history.length} / 60 PTS</Badge>
            <Button variant="secondary" onClick={() => setShowRaw((v) => !v)}>
              <Icon name="terminal" size={13} />
              {showRaw ? "隐藏原始数据" : "查看原始 Prometheus"}
            </Button>
          </>
        }
      />

      {error && (
        <p className="rounded-lg border border-amber/25 bg-amber/6 px-3 py-2 font-mono text-[10px] text-amber">
          最近一次拉取失败：{error}（展示的是上一次成功数据）
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="在途请求"
          value={latest ? latest.active_requests : "—"}
          hint="gauge · 当前并发"
          tone="cyan"
        >
          <Sparkline data={active} height={30} stroke="var(--ui-chart-2)" />
        </MetricCard>
        <MetricCard
          label="在线 Agent 数"
          value={latest ? latest.agents : "—"}
          hint="gauge · 已注册，含过期"
          tone="ok"
        >
          <Sparkline data={agents} height={30} stroke="var(--ui-chart-1)" />
        </MetricCard>
        <MetricCard
          label="累计请求数"
          value={latest ? latest.request_count.toLocaleString() : "—"}
          hint="counter · since start"
        >
          <Sparkline data={counts} height={30} stroke="var(--ui-chart-3)" />
        </MetricCard>
        <MetricCard
          label="累计转发字节"
          value={latest ? formatBytes(latest.bytes_out) : "—"}
          hint="counter · client bytes"
        >
          <Sparkline data={bytes} height={30} stroke="var(--ui-chart-4)" />
        </MetricCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel>
          <PanelHead
            title="在途请求"
            description="gauge：当前并发转发数"
            right={<Badge tone="cyan">LIVE</Badge>}
          />
          <div className="panel-body">
            {active.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={active} height={116} stroke="var(--ui-chart-2)" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHead
            title="在线 Agent 数"
            description="gauge：已注册 agent 数（含心跳过期）"
            right={<Badge tone="ok">MESH</Badge>}
          />
          <div className="panel-body">
            {agents.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={agents} height={116} stroke="var(--ui-chart-1)" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHead
            title="累计请求数"
            description="counter：自网关启动累计"
            right={<span className="font-mono text-[10px] text-mist-dim">{counts.length} PTS</span>}
          />
          <div className="panel-body">
            {counts.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={counts} height={116} stroke="var(--ui-chart-3)" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHead
            title="累计转发字节"
            description="counter：回传客户端字节数"
            right={<span className="font-mono text-[10px] text-mist-dim">{bytes.length} PTS</span>}
          />
          <div className="panel-body">
            {bytes.length < 2 ? (
              <ChartPending label="启动采样中 · 5s" />
            ) : (
              <Sparkline data={bytes} height={116} stroke="var(--ui-chart-4)" />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        <Panel>
          <PanelHead
            title="状态码分布"
            description="hlmg_requests_total 按状态码"
            right={<Badge>HTTP</Badge>}
          />
          <div className="panel-body">
            {statusItems.length > 0 ? (
              <BarList items={statusItems} />
            ) : (
              <EmptyState title="暂无请求记录" detail="网关收到请求后，这里会出现状态码分布。" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHead title="汇总" description="最近一次成功采样的累计值" />
          <div className="panel-body">
            {latest ? (
              <dl className="space-y-3">
                {[
                  ["累计请求数", latest.request_count.toLocaleString()],
                  [
                    "平均耗时",
                    latest.request_count > 0
                      ? formatDuration(latest.request_duration_ms / latest.request_count)
                      : "—",
                  ],
                  ["累计耗时", formatDuration(latest.request_duration_ms)],
                  ["累计转发", formatBytes(latest.bytes_out)],
                  ["在线 Agents", String(latest.agents)],
                ].map(([k, v]) => (
                  <div
                    key={k}
                    className="flex items-center justify-between border-b border-line-soft pb-2.5 last:border-0 last:pb-0"
                  >
                    <dt className="text-[11px] text-mist">{k}</dt>
                    <dd className="font-mono text-[11px] font-medium tabular-nums text-paper">
                      {v}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <EmptyState title="等待首次采样…" detail="采样器启动后会自动填充。" />
            )}
          </div>
        </Panel>
      </div>

      {showRaw && (
        <Panel>
          <PanelHead
            title="原始 /metrics"
            description="Prometheus 文本格式"
            right={<Badge tone="cyan">RAW</Badge>}
          />
          <div className="p-4">
            <pre className="max-h-96 overflow-auto rounded-lg border border-line bg-ink-950 p-4 font-mono text-[10px] leading-relaxed text-mist">
              {raw ?? (error ? `拉取失败：${error}` : "等待首次采样…")}
            </pre>
          </div>
        </Panel>
      )}
    </div>
  );
}
