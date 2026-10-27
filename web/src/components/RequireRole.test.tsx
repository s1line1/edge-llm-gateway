import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { TestAuthProvider } from "../auth/TestAuthProvider";
import RequireRole from "./RequireRole";

function renderWithRole(role: "super_admin" | "tenant_admin" | "user") {
  return render(
    <MemoryRouter>
      <TestAuthProvider role={role}>
        <RequireRole roles={["super_admin"]}>
          <div>super-only</div>
        </RequireRole>
      </TestAuthProvider>
    </MemoryRouter>,
  );
}

describe("RequireRole", () => {
  it("允许匹配角色", () => {
    renderWithRole("super_admin");
    expect(screen.getByText("super-only")).toBeDefined();
  });

  it("拒绝其他角色并给出工作区入口", () => {
    renderWithRole("user");
    expect(screen.getByText("无权访问这个页面")).toBeDefined();
    expect(screen.getByRole("link", { name: "返回我的工作区" })).toBeDefined();
  });
});
