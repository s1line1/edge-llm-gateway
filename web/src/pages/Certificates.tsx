// Credential Pairs：按需创建 client/server 成对凭证；下载只发生一次。

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  createPkiPair,
  downloadPkiPair,
  fetchPkiStatus,
  listPkiPairs,
  listTenants,
  revokePkiPair,
} from "../api/client";
import type { PkiPair } from "../api/types";
import { useAuth } from "../auth/useAuth";
import { Icon } from "../components/icons";
import { Badge, Button, EmptyState, Field, PageHeader, Panel, PanelHead } from "../components/ui";

function stamp(seconds: number | null): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString();
}

function statusTone(status: PkiPair["status"]): "ok" | "warn" | "err" | "default" {
  if (status === "connected") return "ok";
  if (status === "waiting") return "warn";
  if (status === "revoked" || status === "expired") return "err";
  return "default";
}

export default function Certificates() {
  const { user } = useAuth();
  const isSuper = user?.role === "super_admin";
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [serverName, setServerName] = useState("");
  const [sans, setSans] = useState("");
  const [tenantId, setTenantId] = useState(user?.tenant_id ?? "");
  const [oneTime, setOneTime] = useState<PkiPair | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const statusQuery = useQuery({
    queryKey: ["admin", "pki", "status"],
    queryFn: fetchPkiStatus,
    staleTime: 5000,
  });
  const pairsQuery = useQuery({
    queryKey: ["admin", "pki", "pairs"],
    queryFn: () => listPkiPairs(isSuper ? null : (user?.tenant_id ?? null)),
    staleTime: 5000,
  });
  const tenantsQuery = useQuery({
    queryKey: ["admin", "tenants"],
    queryFn: listTenants,
    enabled: isSuper,
    staleTime: 5000,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["admin", "pki"] });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      createPkiPair({
        name: name.trim(),
        tenant_id: isSuper ? tenantId : (user?.tenant_id ?? ""),
        server_name: serverName.trim(),
        server_sans: sans
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: (pair) => {
      setName("");
      setServerName("");
      setSans("");
      setOneTime(pair);
      invalidate();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokePkiPair(id),
    onSuccess: invalidate,
  });

  const download = async (pair: PkiPair) => {
    setDownloadError(null);
    try {
      const blob = await downloadPkiPair(pair.id);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `hlmg-client-${pair.name}.tar`;
      anchor.click();
      URL.revokeObjectURL(url);
      invalidate();
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : "下载失败");
    }
  };

  const enabled = statusQuery.data?.enabled ?? false;
  const pairs = pairsQuery.data ?? [];

  return (
    <div className="flex flex-col gap-7">
      <PageHeader
        index="07"
        eyebrow="CONTROL / CREDENTIALS"
        title="Credential Pairs"
        description="按需创建 client/server 成对凭证。server 半部分留在 Gateway，client 半部分只下载一次。"
        actions={
          <Badge tone={enabled ? "ok" : "warn"}>{enabled ? "PKI ENABLED" : "PKI DISABLED"}</Badge>
        }
      />

      {!enabled && (
        <div className="rounded-lg border border-amber/25 bg-amber/6 px-4 py-3 text-[11px] leading-relaxed text-amber">
          当前部署未启用 <code className="font-mono">pki.enabled</code>。在
          <code className="mx-1 font-mono">gateway-config.yml</code>
          中启用后重启；启动本身不会生成任何证书。
        </div>
      )}

      {enabled && (
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="panel p-4">
            <div className="micro-label">CREDENTIALS</div>
            <div className="mt-2 font-mono text-2xl text-paper">
              {statusQuery.data?.credentials ?? 0}
            </div>
          </div>
          <div className="panel p-4">
            <div className="micro-label">QUIC TLS</div>
            <div className="mt-2 font-mono text-2xl text-paper">
              {statusQuery.data?.tunnel_ready ? "READY" : "WAITING"}
            </div>
          </div>
          <div className="panel p-4">
            <div className="micro-label">NEXT STEP</div>
            <div className="mt-2 text-[11px] text-mist">
              {pairs.length === 0 ? "创建第一对凭证" : "下载 client 证书并连接"}
            </div>
          </div>
        </div>
      )}

      <Panel>
        <PanelHead
          title="创建凭证对"
          description="每对包含独立 CA、server 证书和 client 证书；server_name 必须是 DNS 名。"
        />
        <div className="panel-body">
          <form
            className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"
            onSubmit={(event) => {
              event.preventDefault();
              createMutation.mutate();
            }}
          >
            <Field label="名称" htmlFor="pki-name">
              <input
                id="pki-name"
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="laptop-1"
                autoComplete="off"
              />
            </Field>
            <Field label="Server name (SNI)" htmlFor="pki-server-name">
              <input
                id="pki-server-name"
                className="input"
                value={serverName}
                onChange={(e) => setServerName(e.target.value)}
                placeholder="gateway.example.com"
                autoComplete="off"
              />
            </Field>
            <Field label="额外 SAN（逗号分隔）" htmlFor="pki-sans">
              <input
                id="pki-sans"
                className="input"
                value={sans}
                onChange={(e) => setSans(e.target.value)}
                placeholder="10.0.0.10"
                autoComplete="off"
              />
            </Field>
            {isSuper ? (
              <Field label="Tenant" htmlFor="pki-tenant">
                <select
                  id="pki-tenant"
                  className="input"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                >
                  <option value="">选择 tenant</option>
                  {(tenantsQuery.data ?? []).map((tenant) => (
                    <option key={tenant.id} value={tenant.id}>
                      {tenant.name}
                    </option>
                  ))}
                </select>
              </Field>
            ) : (
              <Field label="Tenant">
                <div className="flex min-h-10 items-center rounded-lg border border-line bg-ink-950/30 px-3">
                  <Badge tone="cyan">
                    {user?.tenant_name ?? user?.tenant_id ?? "current tenant"}
                  </Badge>
                </div>
              </Field>
            )}
            <div className="flex items-end md:col-span-2 xl:col-span-4">
              <Button
                type="submit"
                disabled={
                  !enabled ||
                  createMutation.isPending ||
                  !name.trim() ||
                  !serverName.trim() ||
                  (isSuper && !tenantId)
                }
              >
                <Icon name="plus" size={13} />
                {createMutation.isPending ? "创建中…" : "创建凭证对"}
              </Button>
              {createMutation.isError && (
                <span className="ml-3 text-[10px] text-coral">
                  {createMutation.error instanceof Error
                    ? createMutation.error.message
                    : "创建失败"}
                </span>
              )}
            </div>
          </form>

          {oneTime && (
            <div className="mt-4 rounded-lg border border-signal/25 bg-signal/6 p-4">
              <div className="text-[12px] font-medium text-paper">凭证已创建</div>
              <p className="mt-1 text-[11px] leading-relaxed text-mist">
                client 私钥只下载一次；下载后服务器会删除它。请立即保存。
              </p>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <Button type="button" onClick={() => void download(oneTime)}>
                  下载 client 包
                </Button>
                <span className="font-mono text-[10px] text-mist-dim">
                  {oneTime.server_name} · {oneTime.serial}
                </span>
              </div>
              {downloadError && <p className="mt-2 text-[10px] text-coral">{downloadError}</p>}
            </div>
          )}
        </div>
      </Panel>

      <Panel>
        <PanelHead
          title="凭证目录"
          description="client 证书只能下载一次；server_name 在吊销后可重新使用。"
          right={<Badge>{pairs.length} PAIRS</Badge>}
        />
        <div className="panel-body">
          {pairsQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取凭证状态。" />
          ) : pairsQuery.isError ? (
            <EmptyState title="加载失败" detail={pairsQuery.error.message} />
          ) : pairs.length === 0 ? (
            <EmptyState
              title="还没有凭证"
              detail="Gateway 启动时不会自动生成 CA 或证书；需要时创建第一对。"
              icon="shield"
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table w-full">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>Tenant</th>
                    <th>Server name</th>
                    <th>状态</th>
                    <th>最后连接</th>
                    <th>client 到期</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {pairs.map((pair) => (
                    <tr key={pair.id}>
                      <td className="font-mono text-[11px] text-paper">{pair.name}</td>
                      <td>
                        <Badge tone="cyan">{pair.tenant_id}</Badge>
                      </td>
                      <td className="font-mono text-[10px] text-mist">{pair.server_name}</td>
                      <td>
                        <Badge tone={statusTone(pair.status)}>{pair.status}</Badge>
                      </td>
                      <td className="font-mono text-[10px] text-mist">
                        {stamp(pair.last_connected_at)}
                      </td>
                      <td className="font-mono text-[10px] text-mist">
                        {stamp(pair.client_not_after)}
                      </td>
                      <td>
                        <div className="flex flex-wrap gap-2">
                          {pair.download_url && pair.status !== "revoked" && (
                            <Button
                              type="button"
                              variant="secondary"
                              onClick={() => void download(pair)}
                            >
                              下载
                            </Button>
                          )}
                          {pair.status !== "revoked" && (
                            <Button
                              type="button"
                              variant="ghost"
                              disabled={revokeMutation.isPending}
                              onClick={() => {
                                if (
                                  window.confirm(`吊销 ${pair.name}？已建立的连接不会立即断开。`)
                                ) {
                                  revokeMutation.mutate(pair.id);
                                }
                              }}
                            >
                              吊销
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
        </div>
      </Panel>
    </div>
  );
}
