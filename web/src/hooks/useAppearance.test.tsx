import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useAppearance } from "./useAppearance";

function mockMedia(initial: boolean) {
  const listeners = new Set<() => void>();
  const media = {
    matches: initial,
    media: "(prefers-color-scheme: dark)",
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
    dispatch(matches: boolean) {
      media.matches = matches;
      listeners.forEach((listener) => listener());
    },
  };
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => media),
  );
  return media;
}

describe("useAppearance", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-accent");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("follows system media changes only while theme is system", () => {
    const media = mockMedia(false);
    const { result } = renderHook(() => useAppearance());
    expect(result.current.resolvedTheme).toBe("light");

    act(() => media.dispatch(true));
    expect(result.current.resolvedTheme).toBe("dark");

    act(() => result.current.setTheme("light"));
    expect(result.current.appearance.theme).toBe("light");
    act(() => media.dispatch(true));
    expect(result.current.resolvedTheme).toBe("light");
  });

  it("keeps working in memory when storage is blocked", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const { result } = renderHook(() => useAppearance());
    expect(result.current.appearance.theme).toBe("system");
    act(() => result.current.setAccent("amber"));
    expect(result.current.appearance.accent).toBe("amber");
  });
});
