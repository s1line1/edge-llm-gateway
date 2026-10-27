// 应用壳：角色感知导航 + 顶部会话状态 + 内容画布。

import { useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/useAuth";
import { useMetricsHistoryOptional } from "../hooks/useMetricsHistory";
import { GatewayMark, Icon, type IconName } from "./icons";
import { Badge, IconButton, StatusPill } from "./ui";

type NavItem = { to: string; label: string; icon: IconName; end?: boolean };

const SUPER_NAV: { label: string; items: NavItem[] }[] = [
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
    items: [
      { to: "/keys", label: "API Keys", icon: "key" },
      { to: "/tenants", label: "Tenants", icon: "shield" },
      { to: "/users", label: "Users", icon: "terminal" },
    ],
  },
];

const TENANT_NAV: { label: string; items: NavItem[] }[] = [
  {
    label: "WORKSPACE",
    items: [
      { to: "/tenants", label: "Tenant", icon: "shield" },
      { to: "/agents", label: "Agents", icon: "edge" },
      { to: "/keys", label: "API Keys", icon: "key" },
      { to: "/users", label: "Users", icon: "terminal" },
    ],
  },
];

const USER_NAV: { label: string; items: NavItem[] }[] = [
  {
    label: "ACCESS",
    items: [{ to: "/my-access", label: "我的访问", icon: "key" }],
  },
];

const PAGE_LABELS: Record<string, string> = {
  "/": "总览",
  "/agents": "Agents",
  "/keys": "API Keys",
  "/metrics": "指标",
  "/tenants": "Tenants",
  "/users": "Users",
  "/my-access": "我的访问",
};

const ROLE_LABELS = {
  super_admin: "SUPER ADMIN",
  tenant_admin: "TENANT ADMIN",
  user: "USER",
} as const;

function navClass({ isActive }: { isActive: boolean }): string {
  return `nav-item ${isActive ? "nav-item-active" : ""}`;
}

export default function Layout() {
  const { user, logout } = useAuth();
  const metrics = useMetricsHistoryOptional();
  const location = useLocation();
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);

  const role = user?.role ?? "user";
  const sections =
    role === "super_admin" ? SUPER_NAV : role === "tenant_admin" ? TENANT_NAV : USER_NAV;
  const current = PAGE_LABELS[location.pathname] ?? "控制台";
  const online = metrics ? metrics.reachable && metrics.latest !== null : false;
  const latest = metrics?.latest ?? null;

  const doLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

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
          {sections.map((section) => (
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
              <span className="font-mono text-[9px] tracking-[0.15em] text-mist-dim">SESSION</span>
              <span
                className={`status-dot ${online ? "status-dot-live" : "status-dot-warn"}`}
                aria-hidden
              />
            </div>
            <div className="mt-2 truncate text-[11px] font-medium text-paper">
              {user?.username ?? "unknown"}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-1.5">
              <Badge tone={role === "super_admin" ? "ok" : "cyan"}>{ROLE_LABELS[role]}</Badge>
              {user?.tenant_name && <Badge>{user.tenant_name}</Badge>}
            </div>
            <div className="mt-3 font-mono text-[9px] leading-relaxed text-mist-dim">
              网关版本 {__GATEWAY_VERSION__}
              <br />
              QUIC 隧道 + mTLS
            </div>
          </div>
          <button
            type="button"
            onClick={() => void doLogout()}
            className="mt-2 flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[11px] text-mist transition-colors hover:bg-ink-800 hover:text-paper"
          >
            <Icon name="logout" size={14} />
            退出登录
          </button>
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
            {metrics?.error && (
              <span
                className="hidden max-w-[180px] truncate font-mono text-[10px] text-amber sm:inline"
                title={metrics.error}
              >
                数据拉取异常
              </span>
            )}
            {role === "super_admin" ? (
              <StatusPill
                ok={online}
                label={online ? `LIVE · ${latest?.agents_healthy ?? 0} EDGES` : "OFFLINE"}
              />
            ) : (
              <Badge tone="cyan">{ROLE_LABELS[role]}</Badge>
            )}
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
