// 「同名不同来源」的渲染契约（2026-10-16，agent-node 身份改动）。
//
// 背景：网关的注册表键从 `agent_id` 变成了 `(agent_id, peer_ip)` —— 同一个 `agent_id` 从两个
// 来源 IP 连进来是**两个并存的节点**，`/admin/agents` 会返回**两行同名**。而本页原先用
// `key={a.agent_id}`，碰上同名两行就会撞 React key：两行被当成同一行，行状态（在线/失联/已满）
// 与子节点会错位。
//
// 这个文件专门钉住两件事：
//   ① 同名两行都能渲染出来，且**没有 duplicate key 警告**（把 key 改回 agent_id 时必须变红）；
//   ② 旧网关（响应里没有 `ip` 字段）仍然能渲染，且不出现 `undefined` 文本。

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentInfo } from "../api/types";

const mocks = vi.hoisted(() => ({ fetchAgents: vi.fn() }));

vi.mock("../api/client", () => ({ fetchAgents: mocks.fetchAgents }));

vi.mock("../hooks/useMetricsHistory", () => ({
  useMetricsHistory: () => ({
    latest: null,
    history: [],
    raw: null,
    error: null,
    reachable: true,
  }),
}));

import Agents from "./Agents";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Agents />
    </QueryClientProvider>,
  );
}

const base: AgentInfo = {
  agent_id: "edge-1",
  models: ["mock-llm"],
  max_concurrency: 4,
  inflight: 0,
  last_seen_secs_ago: 1,
  healthy: true,
};

/// 把 console.error 的调用参数摊平成字符串。放在模块级是为了给出显式类型——
/// `tsc -b`（生产构建）比 vitest 的转译严格，隐式 `any` 会让 `pnpm build` 失败。
function consoleMessages(spy: { mock: { calls: unknown[][] } }): string[] {
  return spy.mock.calls.map((call) => call.map((arg) => String(arg)).join(" "));
}

describe("Agents 页：同名不同来源（D1）与旧网关降级", () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    localStorage.setItem("hlmg.admin.token", "t");
    mocks.fetchAgents.mockReset();
    // React 的重复 key 只经 console.error 暴露，不抛异常；所以必须**断言这条通道干净**，
    // 否则"key 改回 agent_id"这类回归在测试里完全看不见。
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  it("同名两行都渲染，且没有 React duplicate key 警告", async () => {
    mocks.fetchAgents.mockResolvedValue([
      { ...base, ip: "127.0.0.1" },
      { ...base, ip: "127.0.0.2", healthy: false },
    ]);
    renderPage();

    // 两个来源 IP 各出现一次（表格里 IP 是独立单元格）
    expect(await screen.findByText("127.0.0.1")).toBeDefined();
    expect(screen.getByText("127.0.0.2")).toBeDefined();
    // 同名两行：agent_id 出现两次，两行各自的状态都在（一行在线、一行失联）
    expect(screen.getAllByText("edge-1")).toHaveLength(2);
    expect(screen.getByText("在线")).toBeDefined();
    expect(screen.getByText("失联")).toBeDefined();

    const duplicateKey = consoleMessages(errorSpy).filter((m) => /same key|duplicate key/i.test(m));
    expect(
      duplicateKey,
      `同名两行撞了 React key（key 必须含 ip）：${duplicateKey.join(" | ")}`,
    ).toEqual([]);
  });

  it("旧网关缺 ip 字段：仍渲染，且不出现 undefined 文本", async () => {
    // `ip` 省略 —— 模拟本次改动之前的网关响应
    mocks.fetchAgents.mockResolvedValue([base]);
    renderPage();

    expect(await screen.findByText("edge-1")).toBeDefined();
    // 降级显示占位符（`—`，IP 与空模型列都会用它），而不是渲染出 `undefined`
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("undefined");
    expect(consoleMessages(errorSpy), "缺字段时也不该有 React 警告").toEqual([]);
  });
});
