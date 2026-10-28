// React 侧的外观状态：读写本地偏好、应用 DOM 属性、跟随系统主题。

import { useCallback, useEffect, useState } from "react";

import {
  APPEARANCE_STORAGE_KEY,
  applyAppearance,
  readAppearance,
  resolveTheme,
  subscribeSystemTheme,
  writeAppearance,
  type Appearance,
  type AppearanceAccent,
  type AppearanceTheme,
} from "../appearance";

export interface AppearanceState {
  appearance: Appearance;
  resolvedTheme: "light" | "dark";
  setTheme: (theme: AppearanceTheme) => void;
  setAccent: (accent: AppearanceAccent) => void;
  reset: () => void;
}

export function useAppearance(): AppearanceState {
  const [appearance, setAppearance] = useState<Appearance>(() => readAppearance());
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() =>
    resolveTheme(appearance.theme),
  );

  const commit = useCallback((next: Appearance) => {
    setAppearance(next);
    setResolvedTheme(applyAppearance(next));
    writeAppearance(next);
  }, []);

  useEffect(() => {
    applyAppearance(appearance);
  }, [appearance]);

  useEffect(() => {
    if (appearance.theme !== "system") return;
    return subscribeSystemTheme(() => {
      setResolvedTheme(applyAppearance(appearance));
    });
  }, [appearance]);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key !== APPEARANCE_STORAGE_KEY) return;
      const next = readAppearance();
      setAppearance(next);
      setResolvedTheme(applyAppearance(next));
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  return {
    appearance,
    resolvedTheme,
    setTheme: (theme) => commit({ ...appearance, theme }),
    setAccent: (accent) => commit({ ...appearance, accent }),
    reset: () => commit({ theme: "system", accent: "signal" }),
  };
}
