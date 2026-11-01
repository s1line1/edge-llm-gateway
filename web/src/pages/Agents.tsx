// Agents：把每个 edge 当作一张可观测的节点卡，而不是一张通用表格。
// 明细来自控制面 agents 端点，状态结论一律采用网关返回的 healthy。

import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { fetchAgents, scopeForRole } from "../api/client";
import { AgentCard } from "../components/AgentCard";
import { EdgeOrbit } from "../components/EdgeOrbit";
import { agentKey, isAgentFull } from "../components/orbitGeometry";
import { Badge, EmptyState, IconButton, PageHeader, Panel, PanelHead } from "../components/ui";
import { useAuth } from "../auth/useAuth";
import { useMetricsHistoryOptional } from "../hooks/useMetricsHistory";

type Filter = "all" | "healthy" | "full" | "stale";

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "全部" },
  { id: "healthy", label: "可路由" },
  { id: "full", label: "满载" },
  { id: "stale", label: "掉线" },
];

export default function Agents() {
  const { user } = useAuth();
  const scope = user ? scopeForRole(user.role) : "account";
  const metrics = useMetricsHistoryOptional();
  const latest = metrics?.latest ?? null;
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [view, setView] = useState<"grid" | "orbit">("grid");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ["admin", "agents", scope],
    queryFn: () => fetchAgents(scope),
    enabled: !!user,
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
      if (filter === "healthy") return a.healthy && !isAgentFull(a);
      if (filter === "full") return a.healthy && isAgentFull(a);
      if (filter === "stale") return !a.healthy;
      return true;
    });
  }, [agents, filter, search]);

  const effectiveSelectedKey =
    selectedKey && filtered.some((a) => agentKey(a) === selectedKey) ? selectedKey : null;
  const selectedAgent = effectiveSelectedKey
    ? (filtered.find((a) => agentKey(a) === effectiveSelectedKey) ?? null)
    : null;

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
            <div className="orbit-toggle" role="group" aria-label="Agent 视图">
              <button type="button" aria-pressed={view === "grid"} onClick={() => setView("grid")}>
                卡片
              </button>
              <button
                type="button"
                aria-pressed={view === "orbit"}
                onClick={() => setView("orbit")}
              >
                Orbit
              </button>
            </div>
            <Badge tone={latest && latest.agents_healthy > 0 ? "ok" : "warn"}>
              <span
                className={`status-dot ${
                  latest && latest.agents_healthy > 0 ? "status-dot-live" : "status-dot-warn"
                }`}
              />
              {latest
                ? `${latest.agents_healthy} ROUTABLE`
                : `${detailQuery.data?.filter((a) => a.healthy).length ?? 0} ROUTABLE`}
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
            {latest
              ? latest.agents_healthy
              : (detailQuery.data?.filter((a) => a.healthy).length ?? "—")}
          </div>
          <div className="mt-2 hidden text-[10px] leading-relaxed text-mist sm:block">
            可路由（hlmg_agents_healthy），不含心跳过期
          </div>
        </div>
        <div className="panel p-3 sm:p-4">
          <div className="micro-label">在途请求</div>
          <div className="mt-2 metric-value text-paper sm:mt-3">
            {latest
              ? latest.active_requests
              : (detailQuery.data?.reduce((sum, a) => sum + a.inflight, 0) ?? "—")}
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
              ? "来自控制面 agents 端点（每 5 秒刷新）"
              : "未取到 agents 明细（旧版网关或未启用控制面），仅显示汇总"
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

        {view === "grid" && selectedAgent && (
          <div className="orbit-selected-strip">
            <span>
              <span className="micro-label">SELECTED</span>{" "}
              <span className="font-mono text-[11px] text-paper">{selectedAgent.agent_id}</span>
              <span className="ml-2 text-[10px] text-mist">
                {selectedAgent.tenant_id ?? "default"}
              </span>
            </span>
            <button type="button" className="btn btn-secondary" onClick={() => setView("orbit")}>
              查看 Orbit
            </button>
          </div>
        )}

        <div className="panel-body">
          {detailQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取 agents 快照。" />
          ) : detailUnavailable ? (
            <div className="rounded-lg border border-line bg-ink-950/35 p-4">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 text-amber">
                  <span className="status-dot status-dot-warn" />
                </span>
                <div>
                  <p className="text-[12px] font-medium text-paper">
                    <code className="font-mono text-[11px]">控制面 agents 端点</code> 返回 404
                  </p>
                  <p className="mt-1.5 max-w-2xl text-[11px] leading-relaxed text-mist">
                    网关版本较旧，或该部署没有挂载管理接口。在线总数见上方卡片。
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
          ) : view === "orbit" ? (
            <EdgeOrbit
              agents={filtered}
              selectedKey={effectiveSelectedKey}
              onSelect={setSelectedKey}
              onRefetch={() => void detailQuery.refetch()}
              staleAfterLabel="STATUS FROM GATEWAY · NO FRONTEND THRESHOLD"
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {filtered.map((agent) => (
                <AgentCard
                  key={agentKey(agent)}
                  agent={agent}
                  selected={agentKey(agent) === effectiveSelectedKey}
                  onSelect={() => setSelectedKey(agentKey(agent))}
                />
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
