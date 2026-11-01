import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { Tenant } from "../api/types";
import { TestAuthProvider } from "../auth/TestAuthProvider";

const mocks = vi.hoisted(() => ({
  listTenants: vi.fn(),
  createTenant: vi.fn(),
  deleteTenant: vi.fn(),
  rotateAgentToken: vi.fn(),
  updateTenant: vi.fn(),
}));
vi.mock("../api/client", () => ({
  scopeForRole: (role: string) =>
    role === "user" ? "account" : role === "tenant_admin" ? "admin" : "system",
  listTenants: mocks.listTenants,
  createTenant: mocks.createTenant,
  deleteTenant: mocks.deleteTenant,
  rotateAgentToken: mocks.rotateAgentToken,
  updateTenant: mocks.updateTenant,
}));

import Tenants from "./Tenants";

const tenant: Tenant = {
  id: "tenant-a",
  name: "acme",
  created_at: 0,
  enabled: true,
  max_concurrent_requests: 4,
  requests_per_minute: 60,
  key_count: 2,
  user_count: 1,
  agent_count: 1,
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15, requests: 2 },
};

function renderPage(role: "super_admin" | "tenant_admin") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TestAuthProvider role={role}>
        <Tenants />
      </TestAuthProvider>
    </QueryClientProvider>,
  );
}

describe("Tenants page", () => {
  it("super_admin sees provisioning and tenant rows", async () => {
    mocks.listTenants.mockResolvedValue([tenant]);
    renderPage("super_admin");
    expect(await screen.findByText("acme")).toBeDefined();
    expect(screen.getByText("创建 tenant")).toBeDefined();
    expect(screen.getByText("2")).toBeDefined();
  });

  it("tenant_admin does not see the provisioning form", async () => {
    mocks.listTenants.mockResolvedValue([tenant]);
    renderPage("tenant_admin");
    expect(await screen.findByText("acme")).toBeDefined();
    expect(screen.queryByText("创建 tenant")).toBeNull();
  });
});
