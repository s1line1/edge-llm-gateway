// 登录：正常账号密码；首次启动时用 admin_token 创建第一个 super_admin，再走同一套登录。

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { bootstrapAdmin, bootstrapStatus } from "../api/auth";
import { useAuth } from "../auth/useAuth";
import { GatewayMark, Icon } from "../components/icons";
import { Badge, Button, Field } from "../components/ui";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [adminToken, setAdminToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";
  const statusQuery = useQuery({
    queryKey: ["admin", "auth", "status"],
    queryFn: bootstrapStatus,
    retry: false,
    staleTime: 10_000,
  });

  const needsBootstrap = statusQuery.data?.bootstrapped === false;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setLoading(true);
    setError(null);
    try {
      if (needsBootstrap) {
        if (!adminToken.trim()) {
          setError("首次启动需要 gateway-config.yml 中的 admin_token");
          return;
        }
        await bootstrapAdmin(adminToken.trim(), username.trim(), password);
      }
      await login(username.trim(), password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-canvas flex min-h-screen items-stretch px-4 py-4 sm:px-6 lg:px-8">
      <div className="mx-auto grid w-full max-w-6xl overflow-hidden rounded-2xl border border-line bg-ink-900/80 shadow-2xl lg:grid-cols-[1.18fr_0.82fr]">
        <section className="relative hidden flex-col justify-between overflow-hidden border-r border-line p-10 lg:flex">
          <div
            className="pointer-events-none absolute inset-0 opacity-70"
            style={{
              backgroundImage:
                "linear-gradient(rgba(143,162,182,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(143,162,182,0.055) 1px, transparent 1px)",
              backgroundSize: "36px 36px",
            }}
          />
          <div className="relative">
            <div className="flex items-center gap-3">
              <span className="text-signal">
                <GatewayMark size={38} />
              </span>
              <div>
                <div className="font-mono text-[13px] font-semibold tracking-[0.08em] text-paper">
                  EDGE/GATEWAY
                </div>
                <div className="mt-1 font-mono text-[9px] tracking-[0.18em] text-mist-dim">
                  CONTROL PLANE
                </div>
              </div>
            </div>

            <div className="mt-20 max-w-lg">
              <div className="eyebrow">PRIVATE MODELS / PUBLIC EDGE</div>
              <h1 className="mt-4 text-4xl font-[560] leading-[1.06] tracking-[-0.045em] text-paper">
                模型留在边缘，
                <br />
                入口开在公网。
              </h1>
              <p className="mt-5 max-w-md text-[0.82rem] leading-relaxed text-mist">
                网关把 OpenAI 兼容入口、Bearer 认证与 QUIC 隧道接在一起。登录后，租户、用户与 edge
                的边界都按角色收敛。
              </p>
            </div>
          </div>

          <div className="relative grid grid-cols-3 gap-3">
            {[
              ["TRANSPORT", "QUIC + mTLS", "shield"],
              ["ACCESS", "tenant scoped", "edge"],
              ["OBSERVE", "/metrics", "pulse"],
            ].map(([label, value, icon]) => (
              <div key={label} className="rounded-lg border border-line bg-ink-950/35 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[9px] tracking-[0.12em] text-mist-dim">
                    {label}
                  </span>
                  <Icon
                    name={icon as "shield" | "edge" | "pulse"}
                    size={13}
                    className="text-signal"
                  />
                </div>
                <div className="mt-3 font-mono text-[11px] text-mist">{value}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="flex flex-col justify-center bg-ink-950/55 px-5 py-10 sm:px-10 lg:px-12">
          <div className="mx-auto w-full max-w-sm">
            <div className="mb-8 flex items-center justify-between lg:hidden">
              <div className="flex items-center gap-2.5">
                <span className="text-signal">
                  <GatewayMark size={28} />
                </span>
                <span className="font-mono text-[12px] tracking-[0.08em] text-paper">
                  EDGE/GATEWAY
                </span>
              </div>
              <Badge tone="ok">
                <span className="status-dot status-dot-live" />
                AUTH
              </Badge>
            </div>

            <div className="hidden lg:block">
              <div className="eyebrow">{needsBootstrap ? "FIRST RUN" : "AUTHENTICATE"}</div>
              <h2 className="mt-2 text-2xl font-[560] tracking-[-0.035em] text-paper">
                {needsBootstrap ? "初始化超级管理员" : "登录控制台"}
              </h2>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-mist">
              {needsBootstrap
                ? "用户表为空。先用启动配置里的 admin_token 创建第一个 super_admin，之后用账号密码登录。"
                : "使用 dashboard 账号登录。session 存在 HttpOnly cookie 中，不写入 localStorage。"}
            </p>
            {statusQuery.isError && (
              <p className="mt-3 rounded-lg border border-amber/25 bg-amber/6 px-3 py-2 font-mono text-[10px] leading-relaxed text-amber">
                无法读取启动状态：{statusQuery.error.message}
              </p>
            )}

            <form onSubmit={submit} className="mt-7 space-y-4">
              {needsBootstrap && (
                <Field label="Admin Token" htmlFor="admin-token">
                  <input
                    id="admin-token"
                    type="password"
                    value={adminToken}
                    onChange={(e) => setAdminToken(e.target.value)}
                    placeholder="gateway-config.yml 中的 admin_token"
                    autoComplete="off"
                    className="input"
                  />
                </Field>
              )}
              <Field label="用户名" htmlFor="username">
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="例如 alice"
                  autoComplete="username"
                  autoFocus
                  className="input"
                />
              </Field>
              <Field
                label="密码"
                htmlFor="password"
                hint={needsBootstrap ? "至少 12 个字符" : undefined}
              >
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  className="input"
                />
              </Field>

              {error && (
                <p className="rounded-lg border border-coral/25 bg-coral/6 px-3 py-2 font-mono text-[10px] leading-relaxed text-coral">
                  {error}
                </p>
              )}

              <Button
                type="submit"
                disabled={!username.trim() || !password || loading}
                className="w-full"
              >
                <Icon name="arrow" size={13} />
                {loading ? "验证中…" : needsBootstrap ? "初始化并登录" : "登录控制台"}
              </Button>
            </form>

            <div className="mt-7 border-t border-line-soft pt-5">
              <p className="text-[10px] leading-relaxed text-mist-dim">
                session 保存在 HttpOnly cookie；管理请求使用 CSRF double-submit。首次初始化后，
                admin_token 只保留为 break-glass 凭据。
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
