import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  APPEARANCE_STORAGE_KEY,
  DEFAULT_APPEARANCE,
  applyAppearance,
  parseAppearance,
  readAppearance,
  resolveTheme,
  subscribeSystemTheme,
  writeAppearance,
} from "./appearance";

function mockMedia(matches: boolean) {
  const listeners = new Set<() => void>();
  const media = {
    matches,
    media: "(prefers-color-scheme: dark)",
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
    dispatch: () => listeners.forEach((listener) => listener()),
  };
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => media),
  );
  return media;
}

describe("appearance", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-accent");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("defaults to system + signal for missing or invalid storage", () => {
    expect(parseAppearance(null)).toEqual(DEFAULT_APPEARANCE);
    expect(parseAppearance("not json")).toEqual(DEFAULT_APPEARANCE);
    expect(parseAppearance('{"theme":"neon","accent":"purple"}')).toEqual(DEFAULT_APPEARANCE);
  });

  it("keeps valid fields and falls back on invalid fields", () => {
    expect(parseAppearance('{"theme":"light","accent":"cyan"}')).toEqual({
      theme: "light",
      accent: "cyan",
    });
    expect(parseAppearance('{"theme":"dark","accent":"purple"}')).toEqual({
      theme: "dark",
      accent: "signal",
    });
  });

  it("returns the default when storage access throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(readAppearance()).toEqual(DEFAULT_APPEARANCE);
  });

  it("reports write failure instead of throwing", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    expect(writeAppearance({ theme: "light", accent: "amber" })).toBe(false);
  });

  it("resolves system from matchMedia and applies DOM attributes", () => {
    mockMedia(true);
    const meta = document.createElement("meta");
    meta.name = "theme-color";
    document.head.appendChild(meta);
    const resolved = applyAppearance({ theme: "system", accent: "cyan" });
    expect(resolved).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.dataset.accent).toBe("cyan");
    expect(meta.getAttribute("content")).toBe("#06090d");
    meta.remove();
  });

  it("does not let system changes affect an explicit theme", () => {
    const media = mockMedia(true);
    let callback = 0;
    const unsubscribe = subscribeSystemTheme(() => callback++);
    expect(resolveTheme("light")).toBe("light");
    expect(resolveTheme("dark")).toBe("dark");
    media.dispatch();
    expect(callback).toBe(1);
    unsubscribe();
  });

  it("persists and reads the versioned key", () => {
    expect(writeAppearance({ theme: "light", accent: "amber" })).toBe(true);
    expect(localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe('{"theme":"light","accent":"amber"}');
    expect(readAppearance()).toEqual({ theme: "light", accent: "amber" });
  });
});
