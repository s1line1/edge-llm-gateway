// Users：super_admin 管理全平台；tenant_admin 只管理本 tenant 的普通用户。

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { createUser, deleteUser, listTenants, listUsers, updateUser } from "../api/client";
import type { AdminUser, UserRole } from "../api/types";
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

export default function Users() {
  const { user } = useAuth();
  const isSuper = user?.role === "super_admin";
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("user");
  const [tenantId, setTenantId] = useState("");

  const tenantsQuery = useQuery({
    queryKey: ["admin", "tenants"],
    queryFn: listTenants,
    enabled: isSuper,
  });
  const usersQuery = useQuery({
    queryKey: ["admin", "users", tenantId],
    queryFn: () => listUsers(isSuper && tenantId ? tenantId : undefined),
    staleTime: 5000,
  });
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
    void queryClient.invalidateQueries({ queryKey: ["admin", "tenants"] });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      createUser({
        username: username.trim(),
        password,
        role,
        tenant_id: role === "super_admin" ? null : tenantId || undefined,
      }),
    onSuccess: () => {
      setUsername("");
      setPassword("");
      invalidate();
    },
  });

  const updateMutation = useMutation({
    mutationFn: (args: { id: string; patch: Parameters<typeof updateUser>[1] }) =>
      updateUser(args.id, args.patch),
    onSuccess: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteUser(id),
    onSuccess: invalidate,
  });

  const resetPassword = (target: AdminUser) => {
    const next = window.prompt(`为「${target.username}」设置新密码（12–128 字符）：`);
    if (next) updateMutation.mutate({ id: target.id ?? "", patch: { password: next } });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        index="06"
        eyebrow="CONTROL / IDENTITIES"
        title="Users"
        description={
          isSuper
            ? "平台级用户目录。super_admin 可创建任意角色；tenant_admin 只能管理本 tenant 的 user。"
            : "本 tenant 的普通用户。可重置密码、停用或删除；角色变更由 super_admin 执行。"
        }
        actions={
          <>
            <Badge tone="cyan">{usersQuery.data?.length ?? "—"} USERS</Badge>
            <IconButton
              icon="refresh"
              label="刷新用户列表"
              onClick={() => void usersQuery.refetch()}
            />
          </>
        }
      />

      <Panel>
        <PanelHead
          eyebrow="INVITE"
          title="创建用户"
          description={isSuper ? "super_admin 可创建任意角色。" : "tenant_admin 只能创建 user。"}
        />
        <div className="panel-body">
          <form
            className="grid gap-2 sm:grid-cols-[1fr_1fr_0.8fr_0.8fr_auto]"
            onSubmit={(e) => {
              e.preventDefault();
              if (username.trim() && password) createMutation.mutate();
            }}
          >
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="用户名，如 alice"
              autoComplete="off"
              className="input"
            />
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              placeholder="初始密码（至少 12 字符）"
              autoComplete="new-password"
              className="input"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              disabled={!isSuper}
              className="input"
            >
              {isSuper && <option value="super_admin">super_admin</option>}
              {isSuper && <option value="tenant_admin">tenant_admin</option>}
              <option value="user">user</option>
            </select>
            <select
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              disabled={!isSuper || role === "super_admin"}
              className="input"
            >
              <option value="">选择 tenant</option>
              {(tenantsQuery.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <Button
              type="submit"
              disabled={
                !username.trim() ||
                !password ||
                (isSuper && role !== "super_admin" && !tenantId) ||
                createMutation.isPending
              }
            >
              <Icon name="plus" size={13} />
              {createMutation.isPending ? "创建中…" : "创建"}
            </Button>
          </form>
          {createMutation.isError && (
            <p className="mt-2 font-mono text-[10px] text-coral">{createMutation.error.message}</p>
          )}
          {isSuper && (
            <label className="mt-3 flex items-center gap-2 sm:w-72">
              <span className="micro-label shrink-0">FILTER</span>
              <select
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                className="input"
              >
                <option value="">全部 tenant</option>
                {(tenantsQuery.data ?? []).map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      </Panel>

      <Panel>
        <PanelHead title="用户目录" description="密码不会出现在列表或响应中" />
        <div className="panel-body">
          {usersQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取用户列表。" />
          ) : usersQuery.isError ? (
            <EmptyState title={`加载失败：${usersQuery.error.message}`} />
          ) : (usersQuery.data ?? []).length === 0 ? (
            <EmptyState title="暂无用户" detail="在下方创建第一个账号。" icon="terminal" />
          ) : (
            <div className="-mx-4 overflow-x-auto sm:mx-0">
              <table className="data-table min-w-[850px]">
                <thead>
                  <tr>
                    <th>用户名</th>
                    <th>角色</th>
                    <th>Tenant</th>
                    <th>状态</th>
                    <th>最后登录</th>
                    <th className="text-right">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {(usersQuery.data ?? []).map((u) => {
                    const self = u.id === user?.id;
                    return (
                      <tr key={u.id ?? u.username}>
                        <td className="font-mono text-[11px] text-paper">{u.username}</td>
                        <td>
                          <select
                            value={u.role}
                            disabled={!isSuper || self}
                            onChange={(e) => {
                              const next = e.target.value as UserRole;
                              updateMutation.mutate({
                                id: u.id ?? "",
                                patch:
                                  next === "super_admin"
                                    ? { role: next, clear_tenant: true }
                                    : { role: next, tenant_id: u.tenant_id ?? undefined },
                              });
                            }}
                            className="rounded border border-line bg-ink-950/45 px-2 py-1 font-mono text-[10px] text-mist"
                          >
                            {isSuper && <option value="super_admin">super_admin</option>}
                            {isSuper && <option value="tenant_admin">tenant_admin</option>}
                            <option value="user">user</option>
                          </select>
                        </td>
                        <td>{u.tenant_name ? <Badge tone="cyan">{u.tenant_name}</Badge> : "—"}</td>
                        <td>
                          <Badge tone={u.enabled ? "ok" : "warn"}>
                            {u.enabled ? "启用" : "禁用"}
                          </Badge>
                        </td>
                        <td className="font-mono text-[10px] text-mist">
                          {u.last_login_at
                            ? new Date(u.last_login_at * 1000).toLocaleString()
                            : "从未"}
                        </td>
                        <td>
                          <div className="flex justify-end gap-1.5">
                            <Button variant="secondary" onClick={() => resetPassword(u)}>
                              改密
                            </Button>
                            {!self && (
                              <Button
                                variant="secondary"
                                disabled={updateMutation.isPending}
                                onClick={() =>
                                  updateMutation.mutate({
                                    id: u.id ?? "",
                                    patch: { enabled: !u.enabled },
                                  })
                                }
                              >
                                {u.enabled ? "禁用" : "启用"}
                              </Button>
                            )}
                            {!self && (
                              <Button
                                variant="danger"
                                disabled={deleteMutation.isPending}
                                onClick={() => {
                                  if (
                                    confirm(
                                      `删除用户「${u.username}」？其 session 与名下 key 会一并失效。`,
                                    )
                                  ) {
                                    deleteMutation.mutate(u.id ?? "");
                                  }
                                }}
                              >
                                删除
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {(updateMutation.isError || deleteMutation.isError) && (
            <p className="mt-3 font-mono text-[10px] text-coral">
              {updateMutation.error?.message ?? deleteMutation.error?.message}
            </p>
          )}
        </div>
      </Panel>
    </div>
  );
}
