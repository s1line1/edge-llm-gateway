import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AppearanceMenu from "./AppearanceMenu";

function mockSystemDark() {
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({
      matches: true,
      media: "(prefers-color-scheme: dark)",
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    })),
  );
}

describe("AppearanceMenu", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-accent");
    mockSystemDark();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("opens the dialog and switches theme and accent", () => {
    render(<AppearanceMenu />);
    const trigger = screen.getByRole("button", { name: "外观设置" });
    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "外观设置" })).toBeDefined();

    fireEvent.click(screen.getByRole("button", { name: /浅色/ }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("hlmg.ui.appearance.v1")).toContain('"theme":"light"');

    fireEvent.click(screen.getByRole("button", { name: /青色/ }));
    expect(document.documentElement.dataset.accent).toBe("cyan");
    expect(screen.getByRole("button", { name: /浅色/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("closes on Escape and restores the trigger focus", () => {
    render(<AppearanceMenu />);
    const trigger = screen.getByRole("button", { name: "外观设置" });
    fireEvent.click(trigger);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "外观设置" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("closes on outside mousedown", () => {
    render(<AppearanceMenu />);
    fireEvent.click(screen.getByRole("button", { name: "外观设置" }));
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("dialog", { name: "外观设置" })).toBeNull();
  });

  it("does not expose session or token material", () => {
    render(<AppearanceMenu />);
    fireEvent.click(screen.getByRole("button", { name: "外观设置" }));
    expect(document.body.textContent ?? "").not.toMatch(/hlmg_session|tenant_agent_token|csrf/);
  });
});
