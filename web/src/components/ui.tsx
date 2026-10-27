// 控制台基础组件：面板、页头、指标、状态与操作控件。

import type { ReactNode } from "react";

import { Icon, type IconName } from "./icons";

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>{children}</section>;
}

export function PanelHead({
  eyebrow,
  title,
  description,
  right,
  className = "",
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <header className={`panel-head ${className}`}>
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow-muted mb-1.5">{eyebrow}</div>}
        <h2 className="text-[0.86rem] font-semibold tracking-[-0.01em] text-paper">{title}</h2>
        {description && <p className="mt-1 text-[11px] leading-relaxed text-mist">{description}</p>}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </header>
  );
}

export function PageHeader({
  index,
  eyebrow,
  title,
  description,
  actions,
}: {
  index: string;
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col justify-between gap-5 border-b border-line-soft pb-6 md:flex-row md:items-end">
      <div>
        <div className="flex items-center gap-2.5">
          <span className="font-mono text-[10px] text-mist-dim">{index}</span>
          <span className="h-px w-7 bg-line" />
          <span className="eyebrow">{eyebrow}</span>
        </div>
        <h1 className="page-title">{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

type Tone = "default" | "ok" | "warn" | "err" | "cyan";

const toneText: Record<Tone, string> = {
  default: "text-paper",
  ok: "text-[var(--color-signal)]",
  warn: "text-[var(--color-amber)]",
  err: "text-[var(--color-coral)]",
  cyan: "text-[var(--color-cyan)]",
};

export function MetricCard({
  label,
  value,
  hint,
  tone = "default",
  children,
  className = "",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: Tone;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`panel p-4 ${className}`}>
      <div className="flex items-start justify-between gap-2">
        <span className="micro-label">{label}</span>
        {tone !== "default" && (
          <span
            className={`status-dot ${
              tone === "ok"
                ? "status-dot-live"
                : tone === "err"
                  ? "status-dot-err"
                  : "status-dot-warn"
            }`}
          />
        )}
      </div>
      <div className={`mt-3 metric-value ${toneText[tone]}`}>{value}</div>
      {hint && <div className="mt-2 text-[11px] leading-relaxed text-mist">{hint}</div>}
      {children && <div className="mt-4">{children}</div>}
    </div>
  );
}

export function Badge({
  children,
  tone = "default",
  className = "",
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  const toneClass =
    tone === "ok"
      ? "badge-ok"
      : tone === "warn"
        ? "badge-warn"
        : tone === "err"
          ? "badge-err"
          : tone === "cyan"
            ? "badge-cyan"
            : "";
  return <span className={`badge ${toneClass} ${className}`}>{children}</span>;
}

export function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <Badge tone={ok ? "ok" : "err"}>
      <span className={`status-dot ${ok ? "status-dot-live" : "status-dot-err"}`} />
      {label}
    </Badge>
  );
}

export function Button({
  children,
  onClick,
  disabled,
  variant = "primary",
  type = "button",
  className = "",
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  type?: "button" | "submit";
  className?: string;
  title?: string;
}) {
  const variantClass =
    variant === "primary"
      ? "btn-primary"
      : variant === "secondary"
        ? "btn-secondary"
        : variant === "danger"
          ? "btn-danger"
          : "btn-ghost";
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`btn ${variantClass} ${className}`}
    >
      {children}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  onClick,
  className = "",
  ariaExpanded,
  ariaControls,
}: {
  icon: IconName;
  label: string;
  onClick?: () => void;
  className?: string;
  ariaExpanded?: boolean;
  ariaControls?: string;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      aria-expanded={ariaExpanded}
      aria-controls={ariaControls}
      title={label}
      onClick={onClick}
      className={`icon-btn ${className}`}
    >
      <Icon name={icon} size={15} />
    </button>
  );
}

export function EmptyState({
  title,
  detail,
  icon = "terminal",
}: {
  title: string;
  detail?: string;
  icon?: IconName;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 flex size-9 items-center justify-center rounded-full border border-line bg-ink-900/70 text-mist-dim">
        <Icon name={icon} size={16} />
      </div>
      <p className="text-[0.8rem] font-medium text-mist">{title}</p>
      {detail && (
        <p className="mt-1 max-w-sm text-[11px] leading-relaxed text-mist-dim">{detail}</p>
      )}
    </div>
  );
}

export function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor?: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="micro-label mb-1.5 block text-mist">
        {label}
      </label>
      {children}
      {hint && <div className="mt-1.5 text-[10px] leading-relaxed text-mist-dim">{hint}</div>}
    </div>
  );
}

export function Meter({
  value,
  tone = "ok",
  label,
}: {
  value: number;
  tone?: "ok" | "warn" | "err";
  label?: string;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div
      className={`meter ${tone === "warn" ? "meter-warn" : tone === "err" ? "meter-err" : ""}`}
      role="progressbar"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}
