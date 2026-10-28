// Orbit 的纯几何与状态语义：不碰 DOM，方便把指针角度/节点顺序钉在单测里。

import type { AgentInfo } from "../api/types";

export const ORBIT_MAX_NODES = 12;

export type AgentStatusTone = "ok" | "warn" | "err";
export interface AgentStatus {
  label: "在线" | "失联" | "已满";
  tone: AgentStatusTone;
}

/** 注册表身份：同名不同 IP 是两个节点。 */
export function agentKey(agent: AgentInfo): string {
  return `${agent.agent_id}@${agent.ip ?? ""}`;
}

export function isAgentFull(agent: AgentInfo): boolean {
  return agent.max_concurrency > 0 && agent.inflight >= agent.max_concurrency;
}

/** 状态只由网关给出的 healthy 与容量决定，不在 Orbit 里重算 stale 阈值。 */
export function agentStatus(agent: AgentInfo): AgentStatus {
  if (!agent.healthy) return { label: "失联", tone: "err" };
  if (isAgentFull(agent)) return { label: "已满", tone: "warn" };
  return { label: "在线", tone: "ok" };
}

export function orbitAgents(
  agents: AgentInfo[],
  max = ORBIT_MAX_NODES,
): { visible: AgentInfo[]; hidden: number } {
  const limit = Math.max(0, Math.floor(max));
  return {
    visible: agents.slice(0, limit),
    hidden: Math.max(0, agents.length - limit),
  };
}

/**
 * index 0 在 12 点方向，顺时针等距。
 * 返回从 12 点开始、顺时针的弧度，范围 [0, 2π)。
 */
export function angleForIndex(index: number, count: number): number {
  if (count <= 0) return 0;
  const normalized = ((index % count) + count) % count;
  return (normalized / count) * Math.PI * 2;
}

/** 半径为 `radius` 的圆上，节点相对圆心的坐标；0 在 12 点。 */
export function pointForIndex(
  index: number,
  count: number,
  radius: number,
): { x: number; y: number } {
  const angle = angleForIndex(index, count);
  return {
    x: Math.sin(angle) * radius,
    y: -Math.cos(angle) * radius,
  };
}

/**
 * 把相对圆心的指针坐标映射到最近的节点。
 * 0 在 12 点，顺时针；`atan2` 的 -π/2 偏移把坐标轴转成表盘角度。
 */
export function indexFromPointer(dx: number, dy: number, count: number): number {
  if (count <= 0) return 0;
  if (!Number.isFinite(dx) || !Number.isFinite(dy)) return 0;
  if (dx === 0 && dy === 0) return 0;
  const angle = Math.atan2(dy, dx) + Math.PI / 2;
  const turns = (((angle / (Math.PI * 2)) % 1) + 1) % 1;
  return Math.round(turns * count) % count;
}
