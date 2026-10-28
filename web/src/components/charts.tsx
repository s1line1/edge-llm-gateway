// 轻量 SVG 图表：无外部依赖，保持控制台的细线与单色信号风格。

import { useId } from "react";

export function Sparkline({
  data,
  width = 320,
  height = 56,
  stroke = "var(--ui-chart-1)",
  fill = true,
}: {
  data: number[];
  width?: number;
  height?: number;
  stroke?: string;
  fill?: boolean;
}) {
  const rawId = useId();
  const gid = `signal-${rawId.replace(/[^a-zA-Z0-9]/g, "")}`;

  if (data.length === 0) {
    return (
      <div className="flex h-14 items-center justify-center font-mono text-[10px] text-mist-dim">
        采样中…
      </div>
    );
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const pad = 3;
  const stepX = data.length > 1 ? (width - pad * 2) / (data.length - 1) : 0;
  const y = (v: number) => height - pad - ((v - min) / span) * (height - pad * 2);

  const points = data.map((v, i) => `${(pad + i * stepX).toFixed(1)},${y(v).toFixed(1)}`);
  const area =
    data.length > 1
      ? `M ${pad} ${height - pad} L ${points.join(" L ")} L ${width - pad} ${height - pad} Z`
      : "";

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width="100%"
      height={height}
      preserveAspectRatio="none"
      aria-hidden
      className="block"
    >
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={stroke} stopOpacity="0.22" />
          <stop offset="100%" stopColor={stroke} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        d={`M ${pad} ${height - pad} L ${width - pad} ${height - pad}`}
        stroke="var(--ui-line)"
        strokeWidth="1"
        strokeDasharray="2 4"
      />
      {fill && data.length > 1 && <path d={area} fill={`url(#${gid})`} />}
      {data.length === 1 ? (
        <>
          <path
            d={`M ${pad} ${height / 2} L ${width - pad} ${height / 2}`}
            stroke="var(--ui-line-soft)"
            strokeWidth="1"
            strokeDasharray="2 5"
          />
          <circle cx={width / 2} cy={height / 2} r="2.4" fill={stroke} />
        </>
      ) : (
        <polyline
          points={points.join(" ")}
          fill="none"
          stroke={stroke}
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  );
}

/** 采样点不足两个时的图表占位：明确告诉用户还要等多久，而不是留一块空白。 */
export function ChartPending({ label = "等待第二个采样点…" }: { label?: string }) {
  return (
    <div className="surface-soft flex h-full min-h-24 items-center justify-center rounded-lg border border-dashed border-line-soft">
      <span className="font-mono text-[10px] tracking-[0.06em] text-mist-dim">{label}</span>
    </div>
  );
}

/** 横排条形图（状态码分布等），值为整数。 */
export function BarList({ items }: { items: { label: string; value: number; color?: string }[] }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="space-y-3">
      {items.map((it) => {
        const isError = Number(it.label) >= 400;
        return (
          <div key={it.label} className="grid grid-cols-[38px_1fr_58px] items-center gap-3">
            <span className={`font-mono text-[11px] ${isError ? "text-coral" : "text-mist"}`}>
              {it.label}
            </span>
            <div className="h-1.5 overflow-hidden rounded-full bg-ink-700">
              <div
                className="h-full rounded-full transition-[width] duration-500"
                style={{
                  width: `${(it.value / max) * 100}%`,
                  background: it.color ?? (isError ? "var(--ui-coral)" : "var(--ui-accent)"),
                }}
                title={`${it.label}: ${it.value}`}
              />
            </div>
            <span className="text-right font-mono text-[11px] tabular-nums text-mist">
              {it.value.toLocaleString()}
            </span>
          </div>
        );
      })}
    </div>
  );
}
