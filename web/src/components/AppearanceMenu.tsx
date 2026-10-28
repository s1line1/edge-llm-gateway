// 外观设置：主题（跟随系统/浅色/深色）与强调色。偏好只存浏览器本地。

import { useEffect, useRef, useState } from "react";

import { useAppearance } from "../hooks/useAppearance";
import type { AppearanceAccent, AppearanceTheme } from "../appearance";
import { Icon } from "./icons";

const THEMES: { id: AppearanceTheme; label: string }[] = [
  { id: "system", label: "跟随系统" },
  { id: "light", label: "浅色" },
  { id: "dark", label: "深色" },
];

const ACCENTS: { id: AppearanceAccent; label: string }[] = [
  { id: "signal", label: "青柠" },
  { id: "cyan", label: "青色" },
  { id: "amber", label: "琥珀" },
];

export default function AppearanceMenu() {
  const { appearance, resolvedTheme, setTheme, setAccent, reset } = useAppearance();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const close = () => {
    setOpen(false);
    triggerRef.current?.focus();
  };

  return (
    <div ref={rootRef} className="appearance-root">
      <button
        ref={triggerRef}
        type="button"
        className="appearance-trigger"
        aria-label="外观设置"
        aria-haspopup="dialog"
        aria-expanded={open}
        title="外观设置"
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name={resolvedTheme === "dark" ? "moon" : "sun"} size={15} />
        <span className="appearance-trigger-label">外观</span>
      </button>

      {open && (
        <div className="appearance-panel" role="dialog" aria-label="外观设置">
          <div className="appearance-head">
            <div>
              <div className="eyebrow-muted">APPEARANCE</div>
              <div className="appearance-title">界面外观</div>
            </div>
            <button type="button" className="icon-btn" aria-label="关闭外观设置" onClick={close}>
              <Icon name="close" size={13} />
            </button>
          </div>

          <div className="appearance-section">
            <div className="micro-label mb-2">主题</div>
            <div className="appearance-segments" role="group" aria-label="主题">
              {THEMES.map((theme) => (
                <button
                  key={theme.id}
                  type="button"
                  aria-pressed={appearance.theme === theme.id}
                  onClick={() => setTheme(theme.id)}
                >
                  <Icon
                    name={theme.id === "system" ? "display" : theme.id === "light" ? "sun" : "moon"}
                    size={12}
                  />
                  {theme.label}
                </button>
              ))}
            </div>
          </div>

          <div className="appearance-section">
            <div className="micro-label mb-2">强调色</div>
            <div className="appearance-accents" role="group" aria-label="强调色">
              {ACCENTS.map((accent) => (
                <button
                  key={accent.id}
                  type="button"
                  aria-pressed={appearance.accent === accent.id}
                  onClick={() => setAccent(accent.id)}
                  title={accent.label}
                >
                  <span className={`appearance-swatch appearance-swatch-${accent.id}`} />
                  <span>{accent.label}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="appearance-foot">
            <span className="appearance-foot-note">只保存在本浏览器</span>
            <button type="button" className="btn btn-ghost" onClick={reset}>
              恢复默认
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
