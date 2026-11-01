// 普通用户的工作区：自己的 key、用量与密码。

import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { changePassword } from "../api/auth";
import { listKeys, listUsage } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { Icon } from "../components/icons";
import { Badge, Button, EmptyState, PageHeader, Panel, PanelHead } from "../components/ui";

export default function MyAccess() {
  const { user } = useAuth();
  const keysQuery = useQuery({
    queryKey: ["admin", "keys", "mine"],
    queryFn: () => listKeys("account"),
    enabled: !!user,
  });
  const usageQuery = useQuery({
    queryKey: ["admin", "usage", "mine"],
    queryFn: () => listUsage("account"),
    enabled: !!user,
  });
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const passwordMutation = useMutation({
    mutationFn: () => changePassword(current, next),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setMessage("密码已更新；其他 session 已撤销。");
    },
  });

  const totals = (usageQuery.data ?? []).reduce(
    (sum, u) => ({
      prompt: sum.prompt + u.prompt_tokens,
      completion: sum.completion + u.completion_tokens,
      requests: sum.requests + u.requests,
    }),
    { prompt: 0, completion: 0, requests: 0 },
  );

  return (
    <div className="space-y-6">
      <PageHeader
        index="07"
        eyebrow="ACCESS / PERSONAL"
        title="我的访问"
        description="查看自己的 API Key 与用量，并更新登录密码。租户、用户和 agent 管理不在这个角色范围内。"
        actions={
          <>
            <Badge tone="cyan">{user?.tenant_name ?? "tenant"}</Badge>
            <Link to="/keys" className="btn btn-secondary">
              <Icon name="key" size={13} />
              管理我的 Key
            </Link>
          </>
        }
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="panel p-4">
          <div className="micro-label">我的 Keys</div>
          <div className="mt-3 metric-value text-paper">{keysQuery.data?.length ?? "—"}</div>
          <div className="mt-2 text-[10px] text-mist">仅显示 owner_user_id = 当前用户</div>
        </div>
        <div className="panel p-4">
          <div className="micro-label">累计 Token</div>
          <div className="mt-3 metric-value text-signal">
            {(totals.prompt + totals.completion).toLocaleString()}
          </div>
          <div className="mt-2 text-[10px] text-mist">
            prompt {totals.prompt.toLocaleString()} · completion{" "}
            {totals.completion.toLocaleString()}
          </div>
        </div>
        <div className="panel p-4">
          <div className="micro-label">累计请求</div>
          <div className="mt-3 metric-value text-paper">{totals.requests.toLocaleString()}</div>
          <div className="mt-2 text-[10px] text-mist">来自自己的 key</div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        <Panel>
          <PanelHead title="我的 Keys" description="只展示你名下的凭据" />
          <div className="panel-body">
            {keysQuery.isPending ? (
              <EmptyState title="加载中…" detail="正在读取你的 key。" />
            ) : keysQuery.isError ? (
              <EmptyState title={`加载失败：${keysQuery.error.message}`} />
            ) : (keysQuery.data ?? []).length === 0 ? (
              <EmptyState
                title="还没有自己的 Key"
                detail="到 API Keys 页面创建一枚；它会自动归属当前账号。"
                icon="key"
              />
            ) : (
              <div className="space-y-2">
                {(keysQuery.data ?? []).map((k) => (
                  <div
                    key={k.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line-soft bg-ink-950/30 px-3 py-2.5"
                  >
                    <div>
                      <div className="text-[11px] font-medium text-paper">{k.name}</div>
                      <div className="mt-0.5 font-mono text-[9px] text-mist-dim">
                        {k.id} · {k.prefix}
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge tone={k.enabled ? "ok" : "default"}>
                        {k.enabled ? "启用" : "禁用"}
                      </Badge>
                      <div className="mt-1 font-mono text-[9px] text-mist-dim">
                        {k.usage.total_tokens.toLocaleString()} tok
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHead title="修改密码" description="需要当前密码；成功后撤销其他 session" />
          <div className="panel-body">
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                setMessage(null);
                if (current && next) passwordMutation.mutate();
              }}
            >
              <label className="block">
                <span className="micro-label mb-1.5 block">当前密码</span>
                <input
                  type="password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  autoComplete="current-password"
                  className="input"
                />
              </label>
              <label className="block">
                <span className="micro-label mb-1.5 block">新密码（12–128 字符）</span>
                <input
                  type="password"
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  autoComplete="new-password"
                  className="input"
                />
              </label>
              {passwordMutation.isError && (
                <p className="font-mono text-[10px] text-coral">{passwordMutation.error.message}</p>
              )}
              {message && <p className="font-mono text-[10px] text-signal">{message}</p>}
              <Button
                type="submit"
                disabled={!current || !next || passwordMutation.isPending}
                className="w-full"
              >
                {passwordMutation.isPending ? "更新中…" : "更新密码"}
              </Button>
            </form>
          </div>
        </Panel>
      </div>
    </div>
  );
}
