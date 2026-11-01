import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PasswordResetDialog } from "./PasswordResetDialog";

function setup(overrides: Partial<Parameters<typeof PasswordResetDialog>[0]> = {}) {
  const props = {
    username: "alice",
    pending: false,
    error: null,
    onCancel: vi.fn(),
    onSubmit: vi.fn(),
    ...overrides,
  };
  render(<PasswordResetDialog {...props} />);
  return props;
}

describe("PasswordResetDialog", () => {
  it("renders an accessible dialog and labeled password field", () => {
    setup();
    expect(screen.getByRole("dialog", { name: "修改密码：alice" })).toBeDefined();
    expect((screen.getByLabelText("新密码") as HTMLInputElement).type).toBe("password");
  });

  it("rejects passwords outside 12–128 characters", () => {
    const props = setup();
    fireEvent.change(screen.getByLabelText("新密码"), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));
    expect(screen.getByRole("alert").textContent).toContain("密码长度必须为 12–128 个字符");
    expect(props.onSubmit).not.toHaveBeenCalled();
  });

  it("submits a valid password", () => {
    const props = setup();
    fireEvent.change(screen.getByLabelText("新密码"), {
      target: { value: "correct horse battery" },
    });
    fireEvent.click(screen.getByRole("button", { name: "更新密码" }));
    expect(props.onSubmit).toHaveBeenCalledWith("correct horse battery");
  });

  it("shows pending state and disables actions", () => {
    setup({ pending: true, error: "server error" });
    expect((screen.getByRole("button", { name: "更新中…" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect((screen.getByRole("button", { name: "取消" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("alert").textContent).toContain("server error");
  });

  it("cancels with the Cancel button, Escape, and overlay click", () => {
    const props = setup();
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    fireEvent.keyDown(document, { key: "Escape" });
    fireEvent.click(screen.getByTestId("password-reset-overlay"));
    expect(props.onCancel).toHaveBeenCalledTimes(3);
  });

  it("does not cancel with Escape while pending", () => {
    const props = setup({ pending: true });
    fireEvent.keyDown(document, { key: "Escape" });
    fireEvent.click(screen.getByTestId("password-reset-overlay"));
    expect(props.onCancel).not.toHaveBeenCalled();
  });
});
