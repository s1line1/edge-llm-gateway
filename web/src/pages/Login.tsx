// 登录：网关控制台的唯一入口。左侧是产品拓扑，右侧只做一件事——验证 admin token。

import { useState } from "react";
import type { FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { listKeys } from "../api/client";
import { GatewayMark, Icon } from "../components/icons";
import { Badge, Button, Field } from "../components/ui";
import { useSetAdminToken } from "../hooks/useAdminToken";

export default function Login() {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const saveToken = useSetAdminToken();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = token.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      await listKeys(trimmed);
      saveToken(trimmed);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败，请检查 admin_token");
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
                网关把 OpenAI 兼容入口、Bearer 认证与 QUIC 隧道接在一起。你在这里看到的每个数字，
                都来自同一条请求路径。
              </p>
            </div>
          </div>

          <div className="relative grid grid-cols-3 gap-3">
            {[
              ["TRANSPORT", "QUIC + mTLS", "shield"],
              ["ROUTING", "edge-local", "edge"],
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
              <div className="eyebrow">AUTHENTICATE</div>
              <h2 className="mt-2 text-2xl font-[560] tracking-[-0.035em] text-paper">
                管理员登录
              </h2>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-mist">
              使用 gateway-config.yml 中配置的 admin_token。它只用于调用
              /admin/*，不会进入模型请求。
            </p>

            <form onSubmit={submit} className="mt-7 space-y-4">
              <Field label="Admin Token" htmlFor="admin-token">
                <input
                  id="admin-token"
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="启动网关时配置的 admin_token"
                  autoComplete="current-password"
                  autoFocus
                  className="input"
                />
              </Field>

              {error && (
                <p className="rounded-lg border border-coral/25 bg-coral/6 px-3 py-2 font-mono text-[10px] leading-relaxed text-coral">
                  {error}
                </p>
              )}

              <Button type="submit" disabled={!token.trim() || loading} className="w-full">
                <Icon name="arrow" size={13} />
                {loading ? "验证中…" : "登录控制台"}
              </Button>
            </form>

            <div className="mt-7 border-t border-line-soft pt-5">
              <p className="text-[10px] leading-relaxed text-mist-dim">
                token 保存在本浏览器 localStorage，仅用于调用 /admin/*。部署时在 gateway-config.yml
                中配置，可用{" "}
                <code className="rounded bg-ink-800 px-1 py-0.5 font-mono text-[9px] text-mist">
                  openssl rand -hex 32
                </code>{" "}
                生成。
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
