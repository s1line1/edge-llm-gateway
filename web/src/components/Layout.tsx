// 应用壳：左侧控制台导航 + 顶部实时状态条 + 内容画布。

import { useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { useAdminToken, useSetAdminToken } from "../hooks/useAdminToken";
import { useMetricsHistory } from "../hooks/useMetricsHistory";
import { GatewayMark, Icon, type IconName } from "./icons";
import { IconButton, StatusPill } from "./ui";

const NAV_SECTIONS: {
  label: string;
  items: { to: string; label: string; icon: IconName; end?: boolean }[];
}[] = [
  {
    label: "OBSERVE",
    items: [
      { to: "/", label: "总览", icon: "overview", end: true },
      { to: "/agents", label: "Agents", icon: "edge" },
      { to: "/metrics", label: "指标", icon: "pulse" },
    ],
  },
  {
    label: "CONTROL",
    items: [{ to: "/keys", label: "API Keys", icon: "key" }],
  },
];

const PAGE_LABELS: Record<string, string> = {
  "/": "总览",
  "/agents": "Agents",
  "/keys": "API Keys",
  "/metrics": "指标",
};

function navClass({ isActive }: { isActive: boolean }): string {
  return `nav-item ${isActive ? "nav-item-active" : ""}`;
}

export default function Layout() {
  const { latest, reachable, error } = useMetricsHistory();
  const token = useAdminToken();
  const clearToken = useSetAdminToken();
  const navigate = useNavigate();
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);

  const logout = () => {
    clearToken("");
    navigate("/login", { replace: true });
  };

  const online = reachable && latest !== null;
  const current = PAGE_LABELS[location.pathname] ?? "控制台";

  return (
    <div className="flex min-h-screen bg-ink-950">
      <aside
        id="app-navigation"
        className={`fixed inset-y-0 left-0 z-40 flex w-[248px] shrink-0 flex-col border-r border-line bg-ink-900/95 backdrop-blur-xl transition-transform duration-200 lg:sticky lg:top-0 lg:h-dvh lg:translate-x-0 ${
          navOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center gap-3 border-b border-line-soft px-5 py-5">
          <span className="text-signal">
            <GatewayMark size={32} />
          </span>
          <div className="min-w-0">
            <div className="font-mono text-[12px] font-semibold tracking-[0.08em] text-paper">
              EDGE/GATEWAY
            </div>
            <div className="mt-0.5 font-mono text-[9px] tracking-[0.16em] text-mist-dim">
              CONTROL PLANE
            </div>
          </div>
          <IconButton
            icon="close"
            label="关闭导航"
            onClick={() => setNavOpen(false)}
            className="ml-auto lg:hidden"
          />
        </div>

        <nav className="flex-1 space-y-7 overflow-y-auto px-3 py-6">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              <div className="mb-2 px-2 font-mono text-[9px] tracking-[0.18em] text-mist-dim">
                {section.label}
              </div>
              <div className="space-y-1">
                {section.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    className={navClass}
                    onClick={() => setNavOpen(false)}
                  >
                    <Icon name={item.icon} size={15} />
                    <span>{item.label}</span>
                    {item.to === "/agents" && latest && latest.agents_healthy > 0 && (
                      <span className="ml-auto font-mono text-[10px] text-signal">
                        {latest.agents_healthy}
                      </span>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-line-soft p-3">
          <div className="rounded-lg border border-line bg-ink-850/70 p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[9px] tracking-[0.15em] text-mist-dim">GATEWAY</span>
              <span
                className={`status-dot ${online ? "status-dot-live" : "status-dot-err"}`}
                aria-hidden
              />
            </div>
            <div className="mt-2 flex items-baseline gap-1.5">
              <span className="font-mono text-lg leading-none text-paper">
                {latest ? latest.agents_healthy : "—"}
              </span>
              <span className="text-[10px] text-mist">healthy edges</span>
            </div>
            <div className="mt-2 font-mono text-[9px] leading-relaxed text-mist-dim">
              网关版本 {__GATEWAY_VERSION__}
              <br />
              QUIC 隧道 + mTLS
            </div>
          </div>
          {token && (
            <button
              type="button"
              onClick={logout}
              className="mt-2 flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[11px] text-mist transition-colors hover:bg-ink-800 hover:text-paper"
            >
              <Icon name="logout" size={14} />
              退出登录
            </button>
          )}
        </div>
      </aside>

      {navOpen && (
        <button
          type="button"
          aria-label="关闭导航遮罩"
          className="fixed inset-0 z-30 bg-ink-950/70 backdrop-blur-sm lg:hidden"
          onClick={() => setNavOpen(false)}
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-[62px] items-center justify-between gap-4 border-b border-line bg-ink-950/80 px-4 backdrop-blur-xl sm:px-6 lg:px-9">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="text-signal lg:hidden">
              <GatewayMark size={20} />
            </span>
            <IconButton
              icon="menu"
              label="打开导航"
              onClick={() => setNavOpen(true)}
              ariaExpanded={navOpen}
              ariaControls="app-navigation"
              className="lg:hidden"
            />
            <div className="flex min-w-0 items-center gap-2 font-mono text-[10px] tracking-[0.08em]">
              <span className="hidden text-mist-dim sm:inline">CONTROL PLANE</span>
              <span className="hidden text-line sm:inline">/</span>
              <span className="truncate text-mist">{current}</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {error && (
              <span
                className="hidden max-w-[180px] truncate font-mono text-[10px] text-amber sm:inline"
                title={error}
              >
                数据拉取异常
              </span>
            )}
            <StatusPill
              ok={online}
              label={online ? `LIVE · ${latest.agents_healthy} EDGES` : "OFFLINE"}
            />
          </div>
        </header>

        <main className="app-canvas min-w-0 flex-1">
          <div className="mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 lg:px-9 lg:py-9">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
