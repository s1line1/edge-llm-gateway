import type { AgentInfo } from "../../api/types";
import { agentStatus } from "../orbitGeometry";
import { OrbitBeacon } from "./OrbitBeacon";

export function OrbitCenter({
  selected,
  tenantLabel,
  healthy,
  total,
  inflight,
  registered,
}: {
  selected: AgentInfo | null;
  tenantLabel: string;
  healthy: number;
  total: number;
  inflight: number;
  registered: number;
}) {
  return (
    <div className="orbit-center" data-orbit-center>
      <div className="micro-label">{selected ? "SELECTED" : "FLEET"}</div>
      {selected ? (
        <>
          <div className="orbit-center-title">{selected.agent_id}</div>
          <div className="mt-1 flex items-center justify-center gap-1.5">
            <OrbitBeacon tone={agentStatus(selected).tone} />
            <span className="font-mono text-[10px] text-mist">{agentStatus(selected).label}</span>
          </div>
          <div className="orbit-center-meta">
            <span>{selected.tenant_id ?? "default"}</span>
            <span>{selected.ip ?? "—"}</span>
          </div>
          <div className="orbit-center-readout">
            {selected.inflight} / {selected.max_concurrency === 0 ? "∞" : selected.max_concurrency}
            <span> in flight</span>
          </div>
          <div className="orbit-center-models">
            {selected.models.join(" · ") || "no declared model"}
          </div>
        </>
      ) : (
        <>
          <div className="orbit-center-title">{tenantLabel}</div>
          <div className="orbit-center-readout">
            {healthy} / {total}
            <span> healthy</span>
          </div>
          <div className="orbit-center-meta">
            <span>{inflight} in flight</span>
            <span>{registered} registered</span>
          </div>
        </>
      )}
    </div>
  );
}
