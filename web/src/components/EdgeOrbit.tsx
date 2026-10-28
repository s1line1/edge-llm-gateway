// Agents 的 Orbit 视图：把 radius 当作表盘，节点是可聚焦的真实按钮。
// 纯几何在 edgeOrbit.ts；这里只处理 DOM 事件、中心读数与视觉层。

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { AgentInfo } from "../api/types";
import {
  agentKey,
  agentStatus,
  orbitAgents,
  pointForIndex,
  indexFromPointer,
  type AgentStatusTone,
} from "./orbitGeometry";
import { Icon } from "./icons";
import { Badge, IconButton } from "./ui";

const SVG_SIZE = 400;
const SVG_CENTER = SVG_SIZE / 2;
const SVG_RADIUS = 160;
const NODE_RADIUS = 0.4;

function PixelBeacon({ tone }: { tone: AgentStatusTone }) {
  return (
    <svg viewBox="0 0 8 8" className={`orbit-pixel orbit-pixel-${tone}`} aria-hidden="true">
      <rect x="1" y="1" width="2" height="2" />
      <rect x="5" y="1" width="2" height="2" opacity="0.55" />
      <rect x="1" y="5" width="2" height="2" opacity="0.55" />
      <rect x="5" y="5" width="2" height="2" />
      <rect x="3" y="3" width="2" height="2" opacity="0.9" />
    </svg>
  );
}

function tickLines() {
  return Array.from({ length: 60 }, (_, i) => {
    const angle = (i / 60) * Math.PI * 2 - Math.PI / 2;
    const inner = i % 5 === 0 ? 181 : 186;
    const outer = 191;
    return (
      <line
        key={i}
        x1={SVG_CENTER + Math.cos(angle) * inner}
        y1={SVG_CENTER + Math.sin(angle) * inner}
        x2={SVG_CENTER + Math.cos(angle) * outer}
        y2={SVG_CENTER + Math.sin(angle) * outer}
        className={i % 5 === 0 ? "orbit-tick orbit-tick-major" : "orbit-tick"}
      />
    );
  });
}

export interface EdgeOrbitProps {
  agents: AgentInfo[];
  selectedKey: string | null;
  onSelect: (key: string | null) => void;
  onRefetch?: () => void;
  staleAfterLabel?: string;
}

export function EdgeOrbit({
  agents,
  selectedKey,
  onSelect,
  onRefetch,
  staleAfterLabel,
}: EdgeOrbitProps) {
  const { visible, hidden } = useMemo(() => orbitAgents(agents), [agents]);
  const selectedIndex = visible.findIndex((agent) => agentKey(agent) === selectedKey);
  const selected = selectedIndex >= 0 ? visible[selectedIndex] : null;
  const [focusedIndex, setFocusedIndex] = useState(0);
  const activeIndex = Math.min(
    selectedIndex >= 0 ? selectedIndex : focusedIndex,
    Math.max(0, visible.length - 1),
  );
  const stageRef = useRef<HTMLDivElement>(null);
  const nodeRefs = useRef(new Map<string, HTMLButtonElement>());
  const dragPointer = useRef<number | null>(null);

  const tenantLabel = useMemo(() => {
    const tenants = [...new Set(visible.map((a) => a.tenant_id ?? "default"))];
    return tenants.length === 1 ? tenants[0] : "ALL TENANTS";
  }, [visible]);

  const selectIndex = useCallback(
    (index: number) => {
      if (visible.length === 0) return;
      const normalized = ((index % visible.length) + visible.length) % visible.length;
      const next = visible[normalized];
      const key = agentKey(next);
      onSelect(key);
      setFocusedIndex(normalized);
      requestAnimationFrame(() => nodeRefs.current.get(key)?.focus());
    },
    [onSelect, visible],
  );

  const selectFromPointer = useCallback(
    (clientX: number, clientY: number) => {
      const stage = stageRef.current;
      if (!stage || visible.length === 0) return;
      const rect = stage.getBoundingClientRect();
      const dx = clientX - (rect.left + rect.width / 2);
      const dy = clientY - (rect.top + rect.height / 2);
      selectIndex(indexFromPointer(dx, dy, visible.length));
    },
    [selectIndex, visible.length],
  );

  // Wheel needs a native listener because React's synthetic wheel handler is
  // passive in some browsers; the ring is the only surface that prevents scroll.
  useEffect(() => {
    const stage = stageRef.current;
    if (!stage || visible.length === 0) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      if (event.deltaY === 0) return;
      selectIndex(activeIndex + (event.deltaY > 0 ? 1 : -1));
    };
    stage.addEventListener("wheel", onWheel, { passive: false });
    return () => stage.removeEventListener("wheel", onWheel);
  }, [activeIndex, selectIndex, visible.length]);

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (visible.length === 0) return;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        event.preventDefault();
        selectIndex(activeIndex + 1);
        break;
      case "ArrowLeft":
      case "ArrowUp":
        event.preventDefault();
        selectIndex(activeIndex - 1);
        break;
      case "Home":
        event.preventDefault();
        selectIndex(0);
        break;
      case "End":
        event.preventDefault();
        selectIndex(visible.length - 1);
        break;
      case "Escape":
        event.preventDefault();
        onSelect(null);
        break;
      default:
        break;
    }
  };

  const onPointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest("[data-orbit-center]") || target.closest("[data-orbit-node]")) return;
    dragPointer.current = event.pointerId;
    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // jsdom and older browsers may not implement pointer capture.
    }
    selectFromPointer(event.clientX, event.clientY);
  };

  const onPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragPointer.current !== event.pointerId) return;
    selectFromPointer(event.clientX, event.clientY);
  };

  const endDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragPointer.current !== event.pointerId) return;
    dragPointer.current = null;
    try {
      if (event.currentTarget.hasPointerCapture(event.pointerId)) {
        event.currentTarget.releasePointerCapture(event.pointerId);
      }
    } catch {
      // pointer capture is an enhancement; selection already happened.
    }
  };

  if (visible.length === 0) {
    return (
      <div className="orbit-empty">
        <span className="status-dot status-dot-warn" />
        暂无在线 agent
      </div>
    );
  }

  const healthy = visible.filter((a) => a.healthy).length;
  const inflight = visible.reduce((sum, a) => sum + a.inflight, 0);
  const circumference = 2 * Math.PI * SVG_RADIUS;
  const selectedArc = selectedIndex >= 0 ? circumference / visible.length : 0;

  return (
    <div className="orbit-shell">
      <div className="orbit-stage-wrap">
        {onRefetch && (
          <IconButton
            icon="refresh"
            label="刷新 Orbit 数据"
            onClick={onRefetch}
            className="orbit-refresh"
          />
        )}
        <div
          ref={stageRef}
          className="orbit-stage"
          role="group"
          aria-label="Edge orbit"
          onKeyDown={onKeyDown}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
        >
          <svg viewBox={`0 0 ${SVG_SIZE} ${SVG_SIZE}`} className="orbit-svg" aria-hidden="true">
            <circle cx={SVG_CENTER} cy={SVG_CENTER} r={SVG_RADIUS + 20} className="orbit-halo" />
            <circle cx={SVG_CENTER} cy={SVG_CENTER} r={SVG_RADIUS} className="orbit-ring" />
            <circle
              cx={SVG_CENTER}
              cy={SVG_CENTER}
              r={SVG_RADIUS - 22}
              className="orbit-ring orbit-ring-inner"
            />
            {tickLines()}
            {selectedArc > 0 && (
              <circle
                cx={SVG_CENTER}
                cy={SVG_CENTER}
                r={SVG_RADIUS}
                className="orbit-selected-arc"
                strokeDasharray={`${selectedArc} ${circumference}`}
                strokeDashoffset={-(selectedIndex / visible.length) * circumference}
                transform={`rotate(-90 ${SVG_CENTER} ${SVG_CENTER})`}
              />
            )}
          </svg>

          <div className="orbit-center" data-orbit-center>
            <div className="micro-label">{selected ? "SELECTED" : "FLEET"}</div>
            {selected ? (
              <>
                <div className="orbit-center-title">{selected.agent_id}</div>
                <div className="mt-1 flex items-center justify-center gap-1.5">
                  <PixelBeacon tone={agentStatus(selected).tone} />
                  <span className="font-mono text-[10px] text-mist">
                    {agentStatus(selected).label}
                  </span>
                </div>
                <div className="orbit-center-meta">
                  <span>{selected.tenant_id ?? "default"}</span>
                  <span>{selected.ip ?? "—"}</span>
                </div>
                <div className="orbit-center-readout">
                  {selected.inflight} /{" "}
                  {selected.max_concurrency === 0 ? "∞" : selected.max_concurrency}
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
                  {healthy} / {visible.length}
                  <span> healthy</span>
                </div>
                <div className="orbit-center-meta">
                  <span>{inflight} in flight</span>
                  <span>{agents.length} registered</span>
                </div>
              </>
            )}
          </div>

          {visible.map((agent, index) => {
            const point = pointForIndex(index, visible.length, NODE_RADIUS);
            const key = agentKey(agent);
            const status = agentStatus(agent);
            const isSelected = key === selectedKey;
            return (
              <button
                key={key}
                ref={(node) => {
                  if (node) nodeRefs.current.set(key, node);
                  else nodeRefs.current.delete(key);
                }}
                type="button"
                data-orbit-node
                className={`orbit-node ${isSelected ? "orbit-node-selected" : ""} orbit-node-${status.tone}`}
                style={{
                  left: `${50 + point.x * 100}%`,
                  top: `${50 + point.y * 100}%`,
                }}
                tabIndex={index === activeIndex ? 0 : -1}
                aria-pressed={isSelected}
                aria-label={`${agent.agent_id} · ${status.label} · ${agent.tenant_id ?? "default"} · ${agent.ip ?? "unknown-ip"}`}
                onClick={(event) => {
                  event.stopPropagation();
                  onSelect(key);
                  setFocusedIndex(index);
                }}
              >
                <PixelBeacon tone={status.tone} />
                <span className="orbit-node-label">{agent.agent_id}</span>
                <span className="orbit-node-load">
                  {agent.inflight}/{agent.max_concurrency === 0 ? "∞" : agent.max_concurrency}
                </span>
              </button>
            );
          })}
        </div>
        {hidden > 0 && (
          <div
            className="orbit-overflow"
            title={`${hidden} more agents are hidden; use the card view`}
          >
            +{hidden} MORE
          </div>
        )}
      </div>

      <div className="orbit-side">
        <div className="orbit-legend">
          <Badge tone="ok">
            <span className="status-dot status-dot-live" />
            在线
          </Badge>
          <Badge tone="warn">已满</Badge>
          <Badge tone="err">失联</Badge>
        </div>
        <p className="orbit-hint">
          <Icon name="arrow" size={11} />
          拖动、滚轮或方向键旋转选择；Esc 清除选择。
        </p>
        {staleAfterLabel && <div className="orbit-stale">{staleAfterLabel}</div>}
      </div>
    </div>
  );
}
