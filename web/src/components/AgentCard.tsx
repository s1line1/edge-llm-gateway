import type { AgentInfo } from "../api/types";
import { agentStatus } from "./orbitGeometry";
import { Badge } from "./ui";

export function AgentCard({
  agent,
  selected,
  onSelect,
}: {
  agent: AgentInfo;
  selected: boolean;
  onSelect: () => void;
}) {
  const status = agentStatus(agent);
  const load = agent.max_concurrency > 0 ? (agent.inflight / agent.max_concurrency) * 100 : 0;
  const tenant = agent.tenant_id ?? "default";

  return (
    <article
      className={`panel group flex flex-col p-4 transition-colors hover:border-[var(--ui-line-strong)] ${
        selected ? "border-signal/50 ring-1 ring-signal/20" : ""
      }`}
      tabIndex={0}
      aria-current={selected ? "true" : undefined}
      onClick={onSelect}
      onFocus={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
        }
      }}
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
