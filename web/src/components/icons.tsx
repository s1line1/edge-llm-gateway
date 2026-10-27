// 线性图标：全部内联 SVG，避免为几个图标增加依赖，也保持控制台的笔画一致。

import type { SVGProps } from "react";

export type IconName =
  | "overview"
  | "edge"
  | "key"
  | "pulse"
  | "plus"
  | "copy"
  | "check"
  | "refresh"
  | "logout"
  | "menu"
  | "close"
  | "search"
  | "arrow"
  | "shield"
  | "terminal"
  | "chevron";

const paths: Record<IconName, string[]> = {
  overview: ["M4 4h6v6H4z", "M14 4h6v6h-6z", "M4 14h6v6H4z", "M14 14h6v6h-6z"],
  edge: ["M12 3 20 7.5v9L12 21l-8-4.5v-9L12 3Z", "M8 10.5h8", "M12 7v2.5", "M8 15h8", "M12 14v3"],
  key: ["M14.5 9.5a3.5 3.5 0 1 1-6.9 1L3 15v3h3l1-1v-2h2l1.2-1.2", "M15 9h.01"],
  pulse: ["M3 12h4l2.2-6 4.2 12 2.1-6H21"],
  plus: ["M12 5v14", "M5 12h14"],
  copy: ["M8 8h11v11H8z", "M5 16H4V4h11v1"],
  check: ["m5 12 4 4L19 6"],
  refresh: [
    "M20 7v5h-5",
    "M4 17v-5h5",
    "M6.1 8.5a7 7 0 0 1 11.6-1.5L20 12",
    "M4 12l2.3 5a7 7 0 0 0 11.6-1.5",
  ],
  logout: ["M10 5H5v14h5", "M14 8l4 4-4 4", "M18 12H9"],
  menu: ["M4 7h16", "M4 12h16", "M4 17h16"],
  close: ["M6 6l12 12", "M18 6 6 18"],
  search: ["M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16Z", "m21 21-4.3-4.3"],
  arrow: ["M4 12h16", "m14 6 6 6-6 6"],
  shield: ["M12 3 20 6v6c0 4.5-3.4 7.8-8 9-4.6-1.2-8-4.5-8-9V6l8-3Z", "m9 12 2 2 4-4"],
  terminal: ["M4 5h16v14H4z", "m7 9 2 2-2 2", "M12 13h4"],
  chevron: ["m9 18 6-6-6-6"],
};

export function Icon({
  name,
  size = 16,
  strokeWidth = 1.6,
  ...props
}: { name: IconName; size?: number; strokeWidth?: number } & Omit<
  SVGProps<SVGSVGElement>,
  "name" | "width" | "height"
>) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {paths[name].map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}

/** 产品标记：一个网关核 + 两条向外分叉的 edge 链路。 */
export function GatewayMark({ size = 30 }: { size?: number }) {
  return (
    <svg
      viewBox="0 0 40 40"
      width={size}
      height={size}
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <path
        d="M20 3.5 34 11v18L20 36.5 6 29V11L20 3.5Z"
        stroke="currentColor"
        strokeWidth="1.2"
        opacity="0.55"
      />
      <path d="M20 10v9M20 19l-8 5M20 19l8 5" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="20" cy="20" r="3" fill="currentColor" />
      <circle cx="12" cy="25" r="1.5" fill="currentColor" opacity="0.7" />
      <circle cx="28" cy="25" r="1.5" fill="currentColor" opacity="0.7" />
    </svg>
  );
}
