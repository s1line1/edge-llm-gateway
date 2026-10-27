// 登录页的两种入口：已初始化 → 用户名/密码；首次启动 → admin_token + 首个 super_admin。

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TestAuthProvider } from "../auth/TestAuthProvider";

const mocks = vi.hoisted(() => ({
  bootstrapStatus: vi.fn(),
  bootstrapAdmin: vi.fn(),
}));

vi.mock("../api/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/auth")>();
  return {
    ...actual,
    bootstrapStatus: mocks.bootstrapStatus,
    bootstrapAdmin: mocks.bootstrapAdmin,
  };
});

import Login from "./Login";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/login"]}>
        <TestAuthProvider role="user">
          <Login />
        </TestAuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("登录页", () => {
  beforeEach(() => {
    mocks.bootstrapStatus.mockReset();
    mocks.bootstrapAdmin.mockReset();
  });

  it("已初始化时只显示账号密码", async () => {
    mocks.bootstrapStatus.mockResolvedValue({
      bootstrapped: true,
      break_glass_available: true,
    });
    renderPage();
    expect(await screen.findByRole("heading", { name: "登录控制台" })).toBeDefined();
    expect(screen.queryByLabelText("Admin Token")).toBeNull();
    expect(screen.getByLabelText("用户名")).toBeDefined();
  });

  it("首次启动显示 Admin Token 与初始化动作", async () => {
    mocks.bootstrapStatus.mockResolvedValue({
      bootstrapped: false,
      break_glass_available: true,
    });
    renderPage();
    expect(await screen.findByText("初始化超级管理员")).toBeDefined();
    expect(screen.getByLabelText("Admin Token")).toBeDefined();
    expect(screen.getByRole("button", { name: /初始化并登录/ })).toBeDefined();

    fireEvent.change(screen.getByLabelText("Admin Token"), {
      target: { value: "admin-token" },
    });
    fireEvent.change(screen.getByLabelText("用户名"), {
      target: { value: "root" },
    });
    fireEvent.change(screen.getByLabelText("密码"), {
      target: { value: "correct horse battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: /初始化并登录/ }));
    await vi.waitFor(() =>
      expect(mocks.bootstrapAdmin).toHaveBeenCalledWith(
        "admin-token",
        "root",
        "correct horse battery",
      ),
    );
  });
});
