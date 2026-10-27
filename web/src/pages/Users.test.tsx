import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AdminUser } from "../api/types";
import { TestAuthProvider } from "../auth/TestAuthProvider";

const mocks = vi.hoisted(() => ({
  listUsers: vi.fn(),
  listTenants: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
}));
vi.mock("../api/client", () => ({
  listUsers: mocks.listUsers,
  listTenants: mocks.listTenants,
  createUser: mocks.createUser,
  updateUser: mocks.updateUser,
  deleteUser: mocks.deleteUser,
}));

import Users from "./Users";

const user: AdminUser = {
  id: "u1",
  username: "alice",
  role: "user",
  tenant_id: "tenant-a",
  tenant_name: "tenant-a",
  enabled: true,
  created_at: 0,
  updated_at: 0,
  last_login_at: 0,
};

const tenantAdmin: AdminUser = {
  ...user,
  id: "admin",
  username: "tenant-admin",
  role: "tenant_admin",
};

function renderPage(role: "super_admin" | "tenant_admin") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TestAuthProvider role={role}>
        <Users />
      </TestAuthProvider>
    </QueryClientProvider>,
  );
}

describe("Users page", () => {
  it("renders the directory and create action", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    renderPage("super_admin");
    expect(await screen.findByText("alice")).toBeDefined();
    expect(screen.getByText("创建用户")).toBeDefined();
  });

  it("tenant_admin cannot choose platform roles", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    renderPage("tenant_admin");
    expect(await screen.findByText("alice")).toBeDefined();
    expect(screen.queryByRole("option", { name: "super_admin" })).toBeNull();
    expect(screen.queryByText("选择 tenant")).toBeNull();
    expect(screen.getAllByText("tenant-a").length).toBeGreaterThan(0);
  });

  it("shows the real tenant_admin role when no select is available", async () => {
    mocks.listUsers.mockResolvedValue([tenantAdmin]);
    mocks.listTenants.mockResolvedValue([]);
    renderPage("tenant_admin");
    expect(await screen.findByText("tenant-admin")).toBeDefined();
    expect(screen.getByText("tenant_admin")).toBeDefined();
  });
});
