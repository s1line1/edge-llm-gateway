// Agents：把每个 edge 当作一张可观测的节点卡，而不是一张通用表格。
// 明细来自 /admin/agents，状态结论一律采用网关返回的 healthy。

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { fetchAgents } from "../api/client";
import type { AgentInfo } from "../api/types";
import { Badge, EmptyState, IconButton, PageHeader, Panel, PanelHead } from "../components/ui";
import { useAdminToken } from "../hooks/useAdminToken";
import { useMetricsHistory } from "../hooks/useMetricsHistory";

type Filter = "all" | "healthy" | "full" | "stale";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "全部" },
  { id: "healthy", label: "可路由" },
  { id: "full", label: "满载" },
  { id: "stale", label: "掉线" },
];

function isFull(a: AgentInfo) {
  return a.max_concurrency > 0 && a.inflight >= a.max_concurrency;
}

function statusOf(a: AgentInfo): { label: string; tone: "ok" | "warn" | "err" } {
  if (!a.healthy) return { label: "失联", tone: "err" };
  if (isFull(a)) return { label: "已满", tone: "warn" };
  return { label: "在线", tone: "ok" };
}

function AgentCard({ agent }: { agent: AgentInfo }) {
  const status = statusOf(agent);
  const load = agent.max_concurrency > 0 ? (agent.inflight / agent.max_concurrency) * 100 : 0;
  const rowKey = `${agent.agent_id}@${agent.ip ?? ""}`;
  const tenant = agent.tenant_id ?? "default";

  return (
    <article
      key={rowKey}
      className="panel group flex flex-col p-4 transition-colors hover:border-[#34485a]"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={`status-dot ${
              status.tone === "ok"
                ? "status-dot-live"
                : status.tone === "warn"
                  ? "status-dot-warn"
                  : "status-dot-err"
            }`}
          />
          <h3 className="truncate font-mono text-[12px] font-medium text-paper">
            {agent.agent_id}
          </h3>
        </div>
        <Badge tone={status.tone}>{status.label}</Badge>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Badge tone="cyan">{tenant}</Badge>
        <span className="font-mono text-[10px] text-mist-dim">{agent.ip ?? "—"}</span>
        <span className="text-[10px] text-mist-dim">·</span>
        <span className="font-mono text-[10px] text-mist-dim">{agent.last_seen_secs_ago}s ago</span>
      </div>

      <div className="mt-4 flex flex-wrap gap-1.5">
        {agent.models.length > 0 ? (
          agent.models.map((model) => (
            <span
              key={model}
              className="rounded border border-line bg-ink-900/70 px-1.5 py-1 font-mono text-[10px] text-mist"
            >
              {model}
            </span>
          ))
        ) : (
          <span className="font-mono text-[10px] text-mist-dim">no declared model</span>
        )}
      </div>

      <div className="mt-auto pt-5">
        <div className="mb-2 flex items-end justify-between gap-2">
          <span className="micro-label">CAPACITY</span>
          <span className="font-mono text-[10px] tabular-nums text-mist">
            {agent.inflight}
            <span className="text-mist-dim">
              {" "}
              / {agent.max_concurrency === 0 ? "∞" : agent.max_concurrency}
            </span>
          </span>
        </div>
        <div
          className={`meter ${status.tone === "err" ? "meter-err" : status.tone === "warn" ? "meter-warn" : ""}`}
        >
          <span
            style={{
              width: agent.max_concurrency === 0 ? "8%" : `${Math.max(2, Math.min(100, load))}%`,
            }}
          />
        </div>
        <div className="mt-2 flex items-center justify-between font-mono text-[9px] text-mist-dim">
          <span>{agent.max_concurrency === 0 ? "UNLIMITED" : "ADMISSION"}</span>
          <span>HEARTBEAT {agent.last_seen_secs_ago}s</span>
        </div>
      </div>
    </article>
  );
}

export default function Agents() {
  const token = useAdminToken();
  const { latest } = useMetricsHistory();
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");

  const detailQuery = useQuery({
    queryKey: ["admin", "agents"],
    queryFn: () => fetchAgents(token),
    enabled: !!token,
    refetchInterval: 5000,
    retry: false,
  });

  const hasDetail = detailQuery.data !== null && !detailQuery.isError;
  const detailUnavailable = detailQuery.data === null;
  const agents = useMemo(() => detailQuery.data ?? [], [detailQuery.data]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return agents.filter((a) => {
      if (
        needle &&
        !`${a.agent_id} ${a.tenant_id ?? ""} ${a.ip ?? ""} ${a.models.join(" ")}`
          .toLowerCase()
          .includes(needle)
      ) {
        return false;
      }
      if (filter === "healthy") return a.healthy && !isFull(a);
      if (filter === "full") return a.healthy && isFull(a);
      if (filter === "stale") return !a.healthy;
      return true;
    });
  }, [agents, filter, search]);

  const capacity =
    agents.length > 0
      ? agents.some((a) => a.max_concurrency === 0)
        ? "不限"
        : agents.reduce((sum, a) => sum + (a.max_concurrency || 0), 0)
      : "—";

  return (
    <div className="space-y-6">
      <PageHeader
        index="02"
        eyebrow="OBSERVE / EDGE FLEET"
        title="Agents"
        description="edge-agent 的在线状态、模型声明与并发容量。节点通过 QUIC 反向拨号接入，状态以网关判定为准。"
        actions={
          <>
            <Badge tone={latest && latest.agents_healthy > 0 ? "ok" : "warn"}>
              <span
                className={`status-dot ${
                  latest && latest.agents_healthy > 0 ? "status-dot-live" : "status-dot-warn"
                }`}
              />
              {latest ? `${latest.agents_healthy} ROUTABLE` : "NO TELEMETRY"}
            </Badge>
            <IconButton
              icon="refresh"
              label="刷新 Agent 列表"
              onClick={() => void detailQuery.refetch()}
            />
          </>
        }
      />

      <div className="grid grid-cols-3 gap-2 sm:gap-3">
        <div className="panel p-3 sm:p-4">
          <div className="micro-label">在线 Agent</div>
          <div className="mt-2 metric-value text-signal sm:mt-3">
            {latest ? latest.agents_healthy : "—"}
          </div>
          <div className="mt-2 hidden text-[10px] leading-relaxed text-mist sm:block">
            可路由（hlmg_agents_healthy），不含心跳过期
          </div>
        </div>
        <div className="panel p-3 sm:p-4">
          <div className="micro-label">在途请求</div>
          <div className="mt-2 metric-value text-paper sm:mt-3">
            {latest ? latest.active_requests : "—"}
          </div>
          <div className="mt-2 hidden text-[10px] leading-relaxed text-mist sm:block">
            所有 agent 合计
          </div>
        </div>
        <div className="panel p-3 sm:p-4">
          <div className="micro-label">并发上限</div>
          <div className="mt-2 metric-value text-paper sm:mt-3">{capacity}</div>
          <div className="mt-2 hidden text-[10px] leading-relaxed text-mist sm:block">
            agent 声明值合计，用于 admission control
          </div>
        </div>
      </div>

      <Panel>
        <PanelHead
          title="Agent 明细"
          description={
            hasDetail
              ? "来自 /admin/agents（每 5 秒刷新）"
              : "未取到 /admin/agents 明细（旧版网关或未启用 /admin/*），仅显示汇总"
          }
          right={
            hasDetail ? (
              <Badge tone="cyan">{agents.length} NODES</Badge>
            ) : (
              <Badge tone="warn">DETAIL UNAVAILABLE</Badge>
            )
          }
        />

        {hasDetail && agents.length > 0 && (
          <div className="flex flex-col gap-3 border-b border-line-soft px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap gap-1">
              {FILTERS.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFilter(f.id)}
                  className={`rounded-md border px-2.5 py-1.5 font-mono text-[10px] transition-colors ${
                    filter === f.id
                      ? "border-signal/35 bg-signal/10 text-signal"
                      : "border-transparent text-mist-dim hover:bg-ink-800 hover:text-mist"
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
            <label className="flex items-center gap-2 rounded-md border border-line bg-ink-950/45 px-2.5 py-1.5 sm:w-56">
              <span className="sr-only">搜索 Agent</span>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="搜索 id / ip / model"
                className="min-w-0 flex-1 bg-transparent font-mono text-[10px] text-paper outline-none placeholder:text-mist-dim"
              />
            </label>
          </div>
        )}

        <div className="panel-body">
          {detailQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取 /admin/agents 快照。" />
          ) : detailUnavailable ? (
            <div className="rounded-lg border border-line bg-ink-950/35 p-4">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 text-amber">
                  <span className="status-dot status-dot-warn" />
                </span>
                <div>
                  <p className="text-[12px] font-medium text-paper">
                    <code className="font-mono text-[11px]">GET /admin/agents</code> 返回 404
                  </p>
                  <p className="mt-1.5 max-w-2xl text-[11px] leading-relaxed text-mist">
                    网关版本较旧，或该部署没有配置{" "}
                    <code className="font-mono text-[10px] text-mist">admin_token</code>
                    （/admin/* 未挂载）。在线总数见上方卡片。
                  </p>
                </div>
              </div>
            </div>
          ) : detailQuery.isError ? (
            <EmptyState title={`加载失败：${detailQuery.error.message}`} />
          ) : agents.length === 0 ? (
            <EmptyState
              title="暂无在线 agent"
              detail="在 edge 侧启动 agent 并确认它已连接网关。"
              icon="edge"
            />
          ) : filtered.length === 0 ? (
            <EmptyState title="没有匹配的 agent" detail="调整状态筛选或搜索词。" icon="search" />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {filtered.map((agent) => (
                <AgentCard key={`${agent.agent_id}@${agent.ip ?? ""}`} agent={agent} />
              ))}
            </div>
          )}
        </div>
      </Panel>

      {hasDetail && agents.length > 0 && (
        <p className="flex items-center gap-2 font-mono text-[9px] tracking-[0.08em] text-mist-dim">
          <span className="status-dot status-dot-live" />
          状态来自网关的 agent_stale_secs 判定；前端不做二次阈值计算
        </p>
      )}
    </div>
  );
}
