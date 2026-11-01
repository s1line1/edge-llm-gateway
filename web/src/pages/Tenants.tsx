// Tenants：super_admin 全平台管理；tenant_admin 只读自己的租户并可轮换 agent token。

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  createTenant,
  deleteTenant,
  listTenants,
  rotateAgentToken,
  scopeForRole,
  updateTenant,
} from "../api/client";
import type { Tenant } from "../api/types";
import { useAuth } from "../auth/useAuth";
import { Icon } from "../components/icons";
import {
  Badge,
  Button,
  EmptyState,
  IconButton,
  PageHeader,
  Panel,
  PanelHead,
} from "../components/ui";

function formatUsage(t: Tenant) {
  return `${t.usage.total_tokens.toLocaleString()} tok · ${t.usage.requests.toLocaleString()} req`;
}

export default function Tenants() {
  const { user } = useAuth();
  const isSuper = user?.role === "super_admin";
  const scope = user ? scopeForRole(user.role) : "account";
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [max, setMax] = useState("0");
  const [rpm, setRpm] = useState("0");
  const [token, setToken] = useState<{ label: string; value: string } | null>(null);

  const tenantsQuery = useQuery({
    queryKey: ["admin", "tenants", scope],
    queryFn: () => listTenants(scope),
    staleTime: 5000,
  });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["admin", "tenants"] });

  const createMutation = useMutation({
    mutationFn: () =>
      createTenant(scope, {
        name: name.trim(),
        max_concurrent_requests: Number(max) || 0,
        requests_per_minute: Number(rpm) || 0,
      }),
    onSuccess: (tenant) => {
      setName("");
      if (tenant.agent_token) {
        setToken({ label: `新 tenant ${tenant.name} 的 agent token`, value: tenant.agent_token });
      }
      invalidate();
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (tenant: Tenant) => updateTenant(scope, tenant.id, { enabled: !tenant.enabled }),
    onSuccess: invalidate,
  });

  const rotateMutation = useMutation({
    mutationFn: (tenant: Tenant) => rotateAgentToken(scope, tenant.id),
    onSuccess: (result, tenant) => {
      setToken({ label: `${tenant.name} 的新 agent token`, value: result.agent_token });
      invalidate();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteTenant(scope, id),
    onSuccess: invalidate,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        index="05"
        eyebrow={isSuper ? "CONTROL / TENANTS" : "WORKSPACE / TENANT"}
        title={isSuper ? "Tenants" : "我的租户"}
        description={
          isSuper
            ? "租户是 key、用户与 edge 的授权边界。创建后为它分配 tenant_admin，再签发客户端 key。"
            : "查看当前租户的资源规模，并可轮换 edge agent 的注册 token。"
        }
        actions={
          <>
            <Badge tone="cyan">
              {tenantsQuery.data?.length ?? "—"} {isSuper ? "TENANTS" : "SCOPE"}
            </Badge>
            <IconButton
              icon="refresh"
              label="刷新租户列表"
              onClick={() => void tenantsQuery.refetch()}
            />
          </>
        }
      />

      {isSuper && (
        <Panel>
          <PanelHead
            eyebrow="PROVISION"
            title="创建 tenant"
            description="tenant id 由网关生成；agent token 只在创建时返回一次。"
          />
          <div className="panel-body">
            <form
              className="grid gap-2 sm:grid-cols-[1.4fr_0.7fr_0.7fr_auto]"
              onSubmit={(e) => {
                e.preventDefault();
                if (name.trim()) createMutation.mutate();
              }}
            >
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="tenant 名称，如 acme"
                maxLength={64}
                className="input"
              />
              <input
                value={max}
                onChange={(e) => setMax(e.target.value)}
                type="number"
                min={0}
                placeholder="并发上限"
                className="input"
              />
              <input
                value={rpm}
                onChange={(e) => setRpm(e.target.value)}
                type="number"
                min={0}
                placeholder="req/min"
                className="input"
              />
              <Button type="submit" disabled={!name.trim() || createMutation.isPending}>
                <Icon name="plus" size={13} />
                {createMutation.isPending ? "创建中…" : "创建"}
              </Button>
            </form>
            {createMutation.isError && (
              <p className="mt-2 font-mono text-[10px] text-coral">
                {createMutation.error.message}
              </p>
            )}
            {token && (
              <div className="mt-4 rounded-lg border border-signal/25 bg-signal/6 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] text-signal">{token.label}（仅显示一次）</span>
                  <Button
                    variant="secondary"
                    onClick={() => {
                      void navigator.clipboard?.writeText(token.value);
                    }}
                  >
                    <Icon name="copy" size={12} />
                    复制
                  </Button>
                </div>
                <code className="mt-2 block break-all rounded border border-line bg-ink-950/60 px-2.5 py-2 font-mono text-[10px] text-paper">
                  {token.value}
                </code>
              </div>
            )}
          </div>
        </Panel>
      )}

      <Panel>
        <PanelHead
          title="Tenant 资源"
          description="key / user / agent 计数与累计用量"
          right={<Badge>{isSuper ? "ALL TENANTS" : "OWN TENANT"}</Badge>}
        />
        <div className="panel-body">
          {tenantsQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取 tenant 列表。" />
          ) : tenantsQuery.isError ? (
            <EmptyState title={`加载失败：${tenantsQuery.error.message}`} />
          ) : (tenantsQuery.data ?? []).length === 0 ? (
            <EmptyState title="暂无 tenant" detail="super_admin 可以在上方创建。" icon="shield" />
          ) : (
            <div className="-mx-4 overflow-x-auto sm:mx-0">
              <table className="data-table min-w-[850px]">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>ID</th>
                    <th>状态</th>
                    <th>Keys</th>
                    <th>Users</th>
                    <th>Agents</th>
                    <th>并发 / RPM</th>
                    <th>用量</th>
                    <th className="text-right">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {(tenantsQuery.data ?? []).map((tenant) => (
                    <tr key={tenant.id}>
                      <td className="font-medium text-paper">{tenant.name}</td>
                      <td className="font-mono text-[10px] text-mist">{tenant.id}</td>
                      <td>
                        <Badge tone={tenant.enabled ? "ok" : "warn"}>
                          {tenant.enabled ? "启用" : "禁用"}
                        </Badge>
                      </td>
                      <td className="font-mono text-mist">{tenant.key_count}</td>
                      <td className="font-mono text-mist">{tenant.user_count}</td>
                      <td className="font-mono text-mist">{tenant.agent_count}</td>
                      <td className="font-mono text-[10px] text-mist">
                        {tenant.max_concurrent_requests || "∞"} /{" "}
                        {tenant.requests_per_minute || "∞"}
                      </td>
                      <td className="text-[10px] text-mist">{formatUsage(tenant)}</td>
                      <td>
                        <div className="flex justify-end gap-1.5">
                          {(isSuper || user?.role === "tenant_admin") && (
                            <Button
                              variant="secondary"
                              disabled={rotateMutation.isPending}
                              onClick={() => {
                                if (
                                  confirm(
                                    `轮换 tenant「${tenant.name}」的 agent token？旧 token 立即失效。`,
                                  )
                                ) {
                                  rotateMutation.mutate(tenant);
                                }
                              }}
                            >
                              轮换 token
                            </Button>
                          )}
                          {isSuper && (
                            <Button
                              variant="secondary"
                              disabled={toggleMutation.isPending}
                              onClick={() => toggleMutation.mutate(tenant)}
                            >
                              {tenant.enabled ? "禁用" : "启用"}
                            </Button>
                          )}
                          {isSuper && tenant.id !== "default" && (
                            <Button
                              variant="danger"
                              disabled={deleteMutation.isPending}
                              onClick={() => {
                                if (
                                  confirm(
                                    `删除 tenant「${tenant.name}」？有用户、key 或在线 agent 时会被拒绝。`,
                                  )
                                ) {
                                  deleteMutation.mutate(tenant.id);
                                }
                              }}
                            >
                              删除
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {(createMutation.isError ||
            toggleMutation.isError ||
            deleteMutation.isError ||
            rotateMutation.isError) && (
            <p className="mt-3 font-mono text-[10px] text-coral">
              {createMutation.error?.message ??
                toggleMutation.error?.message ??
                deleteMutation.error?.message ??
                rotateMutation.error?.message}
            </p>
          )}
        </div>
      </Panel>
    </div>
  );
}
