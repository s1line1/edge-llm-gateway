import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AgentInfo } from "../api/types";
import { EdgeOrbit } from "./EdgeOrbit";

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

const agents = [agent(), agent({ agent_id: "edge-2", ip: "127.0.0.2", inflight: 4 })];

describe("EdgeOrbit", () => {
  it("renders accessible nodes and an aggregate center by default", () => {
    render(<EdgeOrbit agents={agents} selectedKey={null} onSelect={() => undefined} />);
    expect(screen.getByText("FLEET")).toBeDefined();
    expect(screen.getByText(/healthy/)).toBeDefined();
    expect(screen.getByRole("group", { name: "Edge orbit" })).toBeDefined();
    expect(screen.getByRole("button", { name: /edge-1 · 在线/ })).toBeDefined();
    expect(screen.getByRole("button", { name: /edge-2 · 已满/ })).toBeDefined();
    expect(screen.getByRole("button", { name: /edge-1/ }).getAttribute("aria-pressed")).toBe(
      "false",
    );
  });

  it("selects a node by click and renders selected details", () => {
    const onSelect = vi.fn();
    const { rerender } = render(
      <EdgeOrbit agents={agents} selectedKey={null} onSelect={onSelect} />,
    );
    const first = screen.getByRole("button", { name: /edge-1/ });
    fireEvent.click(first);
    expect(onSelect).toHaveBeenCalledWith("edge-1@127.0.0.1");

    rerender(<EdgeOrbit agents={agents} selectedKey="edge-1@127.0.0.1" onSelect={onSelect} />);
    expect(screen.getByText("SELECTED")).toBeDefined();
    expect(screen.getByText("SELECTED")).toBeDefined();
    expect(first.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText("mock-llm")).toBeDefined();
  });

  it("supports keyboard and Escape selection", () => {
    const onSelect = vi.fn();
    render(<EdgeOrbit agents={agents} selectedKey={null} onSelect={onSelect} />);
    const first = screen.getByRole("button", { name: /edge-1/ });
    fireEvent.keyDown(first, { key: "ArrowRight" });
    expect(onSelect).toHaveBeenCalledWith("edge-2@127.0.0.2");
    fireEvent.keyDown(first, { key: "Escape" });
    expect(onSelect).toHaveBeenCalledWith(null);
  });

  it("supports wheel selection on the ring", async () => {
    const onSelect = vi.fn();
    render(<EdgeOrbit agents={agents} selectedKey={null} onSelect={onSelect} />);
    const stage = screen.getByRole("group", { name: "Edge orbit" });
    await act(async () => {
      stage.dispatchEvent(new WheelEvent("wheel", { deltaY: 1, bubbles: true, cancelable: true }));
    });
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith("edge-2@127.0.0.2"));
  });

  it("supports pointer selection around the ring", () => {
    const onSelect = vi.fn();
    render(<EdgeOrbit agents={agents} selectedKey={null} onSelect={onSelect} />);
    const stage = screen.getByRole("group", { name: "Edge orbit" });
    vi.spyOn(stage, "getBoundingClientRect").mockReturnValue({
      left: 0,
      top: 0,
      width: 400,
      height: 400,
      right: 400,
      bottom: 400,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    fireEvent.pointerDown(stage, { pointerId: 1, clientX: 200, clientY: 20 });
    expect(onSelect).toHaveBeenCalledWith("edge-1@127.0.0.1");
    fireEvent.pointerMove(stage, { pointerId: 1, clientX: 380, clientY: 200 });
    expect(onSelect).toHaveBeenCalledWith("edge-2@127.0.0.2");
    fireEvent.pointerUp(stage, { pointerId: 1, clientX: 380, clientY: 200 });
  });

  it("renders empty and overflow states", () => {
    const { rerender } = render(
      <EdgeOrbit agents={[]} selectedKey={null} onSelect={() => undefined} />,
    );
    expect(screen.getByText("暂无在线 agent")).toBeDefined();

    const many = Array.from({ length: 13 }, (_, i) => agent({ agent_id: `edge-${i}` }));
    rerender(<EdgeOrbit agents={many} selectedKey={null} onSelect={() => undefined} />);
    expect(screen.getByText("+1 MORE")).toBeDefined();
    expect(screen.getAllByRole("button")).toHaveLength(12);
  });

  it("declares a reduced-motion override for the selected arc", () => {
    const css = readFileSync(resolve(process.cwd(), "src/styles/orbit.css"), "utf8");
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
    expect(css).toMatch(/\.orbit-selected-arc \{\s*transition: none;/);
  });

  it("does not render undefined or credential-like text", () => {
    render(<EdgeOrbit agents={agents} selectedKey={null} onSelect={() => undefined} />);
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("undefined");
    expect(text).not.toMatch(/tenant_agent_token|hlmg_session|hlmg_csrf/);
  });
});
