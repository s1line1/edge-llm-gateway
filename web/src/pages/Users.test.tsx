import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  scopeForRole: (role: string) =>
    role === "user" ? "account" : role === "tenant_admin" ? "admin" : "system",
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

describe("Users page password reset dialog", () => {
  it("opens an in-page dialog with a password input instead of a native prompt", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    const prompt = vi.spyOn(window, "prompt").mockReturnValue(null);
    renderPage("super_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));

    expect(await screen.findByRole("dialog", { name: "修改密码：alice" })).toBeDefined();
    expect(screen.getByLabelText("新密码")).toBeDefined();
    expect(prompt).not.toHaveBeenCalled();
    prompt.mockRestore();
  });

  it("validates the password length before calling the API", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.updateUser.mockReset();
    renderPage("super_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));
    fireEvent.change(screen.getByLabelText("新密码"), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));

    expect(await screen.findByText("密码长度必须为 12–128 个字符")).toBeDefined();
    expect(mocks.updateUser).not.toHaveBeenCalled();
  });

  it("submits the new password with the super_admin system scope and reports success", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.updateUser.mockReset();
    mocks.updateUser.mockResolvedValue(user);
    renderPage("super_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "correct horse battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));

    await waitFor(() =>
      expect(mocks.updateUser).toHaveBeenCalledWith("system", "u1", {
        password: "correct horse battery",
      }),
    );
    expect(await screen.findByText("密码已更新：alice")).toBeDefined();
    expect(screen.queryByRole("dialog", { name: "修改密码：alice" })).toBeNull();
  });

  it("uses the tenant_admin admin scope", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.updateUser.mockReset();
    mocks.updateUser.mockResolvedValue(user);
    renderPage("tenant_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "correct horse battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));

    await waitFor(() =>
      expect(mocks.updateUser).toHaveBeenCalledWith("admin", "u1", {
        password: "correct horse battery",
      }),
    );
  });

  it("cancel closes the dialog without calling the API", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.updateUser.mockReset();
    renderPage("super_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));
    fireEvent.click(screen.getByRole("button", { name: "取消" }));

    expect(screen.queryByRole("dialog", { name: "修改密码：alice" })).toBeNull();
    expect(mocks.updateUser).not.toHaveBeenCalled();
  });

  it("keeps the dialog open and shows the server error when reset fails", async () => {
    mocks.listUsers.mockResolvedValue([user]);
    mocks.listTenants.mockResolvedValue([]);
    mocks.updateUser.mockReset();
    mocks.updateUser.mockRejectedValue(new Error("current password is incorrect"));
    renderPage("super_admin");

    fireEvent.click(await screen.findByRole("button", { name: "改密" }));
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "correct horse battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));

    expect(await screen.findByText("current password is incorrect")).toBeDefined();
    expect(screen.getByRole("dialog", { name: "修改密码：alice" })).toBeDefined();
  });
});
