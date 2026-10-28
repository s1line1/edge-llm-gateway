import { describe, expect, it } from "vitest";

import type { AgentInfo } from "../api/types";
import {
  agentKey,
  agentStatus,
  angleForIndex,
  indexFromPointer,
  isAgentFull,
  orbitAgents,
  pointForIndex,
} from "./orbitGeometry";

function agent(overrides: Partial<AgentInfo> = {}): AgentInfo {
  return {
    agent_id: "edge-1",
    ip: "127.0.0.1",
    models: ["mock-llm"],
    max_concurrency: 4,
    inflight: 1,
    last_seen_secs_ago: 1,
    healthy: true,
    ...overrides,
  };
}

describe("edgeOrbit geometry", () => {
  it("caps visible nodes and reports overflow", () => {
    const agents = Array.from({ length: 15 }, (_, i) => agent({ agent_id: `edge-${i}` }));
    expect(orbitAgents(agents, 12).visible).toHaveLength(12);
    expect(orbitAgents(agents, 12).hidden).toBe(3);
    expect(orbitAgents(agents).visible).toHaveLength(12);
  });

  it("keeps the agent id + ip identity, including duplicate ids", () => {
    const a = agent();
    const b = agent({ ip: "127.0.0.2" });
    expect(agentKey(a)).toBe("edge-1@127.0.0.1");
    expect(agentKey(b)).toBe("edge-1@127.0.0.2");
    expect(agentKey(a)).not.toBe(agentKey(b));
  });

  it("places index 0 at the top and index 1/4 at the right", () => {
    expect(angleForIndex(0, 4)).toBe(0);
    expect(angleForIndex(1, 4)).toBeCloseTo(Math.PI / 2);
    expect(pointForIndex(0, 4, 100).x).toBeCloseTo(0);
    expect(pointForIndex(0, 4, 100).y).toBeCloseTo(-100);
    expect(pointForIndex(1, 4, 100).x).toBeCloseTo(100);
    expect(pointForIndex(1, 4, 100).y).toBeCloseTo(0);
  });

  it("maps cardinal pointers to the expected indices", () => {
    expect(indexFromPointer(0, -100, 4)).toBe(0);
    expect(indexFromPointer(100, 0, 4)).toBe(1);
    expect(indexFromPointer(0, 100, 4)).toBe(2);
    expect(indexFromPointer(-100, 0, 4)).toBe(3);
    expect(indexFromPointer(0, 0, 4)).toBe(0);
    expect(indexFromPointer(0, 0, 0)).toBe(0);
  });

  it("wraps across the top seam", () => {
    expect(indexFromPointer(2, -100, 8)).toBe(0);
    expect(indexFromPointer(-2, -100, 8)).toBe(0);
  });

  it("shares the gateway status semantics", () => {
    expect(agentStatus(agent()).label).toBe("在线");
    expect(agentStatus(agent({ inflight: 4 })).label).toBe("已满");
    expect(agentStatus(agent({ healthy: false })).label).toBe("失联");
    expect(isAgentFull(agent({ max_concurrency: 0, inflight: 99 }))).toBe(false);
  });
});
