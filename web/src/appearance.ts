// 外观偏好：主题 + 强调色。只存浏览器本地，不进入 API 或用户身份。

export type AppearanceTheme = "system" | "light" | "dark";
export type AppearanceAccent = "signal" | "cyan" | "amber";

export interface Appearance {
  theme: AppearanceTheme;
  accent: AppearanceAccent;
}

export const APPEARANCE_STORAGE_KEY = "hlmg.ui.appearance.v1";
export const DEFAULT_APPEARANCE: Appearance = { theme: "system", accent: "signal" };

const THEMES: AppearanceTheme[] = ["system", "light", "dark"];
const ACCENTS: AppearanceAccent[] = ["signal", "cyan", "amber"];
const LIGHT_THEME_COLOR = "#f2eee5";
const DARK_THEME_COLOR = "#06090d";

function isTheme(value: unknown): value is AppearanceTheme {
  return typeof value === "string" && (THEMES as string[]).includes(value);
}

function isAccent(value: unknown): value is AppearanceAccent {
  return typeof value === "string" && (ACCENTS as string[]).includes(value);
}

export function parseAppearance(raw: string | null): Appearance {
  if (!raw) return DEFAULT_APPEARANCE;
  try {
    const value = JSON.parse(raw) as Partial<Appearance> | null;
    if (!value || typeof value !== "object") return DEFAULT_APPEARANCE;
    return {
      theme: isTheme(value.theme) ? value.theme : DEFAULT_APPEARANCE.theme,
      accent: isAccent(value.accent) ? value.accent : DEFAULT_APPEARANCE.accent,
    };
  } catch {
    return DEFAULT_APPEARANCE;
  }
}

export function readAppearance(): Appearance {
  try {
    return parseAppearance(localStorage.getItem(APPEARANCE_STORAGE_KEY));
  } catch {
    return DEFAULT_APPEARANCE;
  }
}

export function writeAppearance(value: Appearance): boolean {
  try {
    localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function resolveTheme(theme: AppearanceTheme): "light" | "dark" {
  if (theme !== "system") return theme;
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyAppearance(appearance: Appearance): "light" | "dark" {
  if (typeof document === "undefined") return resolveTheme(appearance.theme);
  const resolved = resolveTheme(appearance.theme);
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.accent = appearance.accent;
  root.style.colorScheme = resolved;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute("content", resolved === "light" ? LIGHT_THEME_COLOR : DARK_THEME_COLOR);
  }
  return resolved;
}

type MediaQueryListWithLegacy = MediaQueryList & {
  addListener?: (listener: (event: MediaQueryListEvent) => void) => void;
  removeListener?: (listener: (event: MediaQueryListEvent) => void) => void;
};

export function subscribeSystemTheme(callback: () => void): () => void {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return () => undefined;
  }
  const media = window.matchMedia("(prefers-color-scheme: dark)") as MediaQueryListWithLegacy;
  const listener = () => callback();
  if (media.addEventListener) {
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }
  media.addListener?.(listener);
  return () => media.removeListener?.(listener);
}
