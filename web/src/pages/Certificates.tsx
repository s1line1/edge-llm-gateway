// Credential Pairs：页面只负责编排数据、一次性下载和角色差异。

import { useState } from "react";

import type { CreatePkiPairBody, PkiPair } from "../api/types";
import { scopeForRole } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { CreatePairForm } from "../components/certificates/CreatePairForm";
import { OneTimeDownload } from "../components/certificates/OneTimeDownload";
import { PairStatusCards } from "../components/certificates/PairStatusCards";
import { PairTable } from "../components/certificates/PairTable";
import { Badge, PageHeader, Panel, PanelHead } from "../components/ui";
import { downloadPkiBundle, usePki } from "../hooks/usePki";

export default function Certificates() {
  const { user } = useAuth();
  const isSuper = user?.role === "super_admin";
  const scope = user ? scopeForRole(user.role) : "account";
  const pki = usePki(scope, isSuper, user?.tenant_id ?? null);
  const [oneTime, setOneTime] = useState<PkiPair | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const enabled = pki.statusQuery.data?.enabled ?? false;
  const pairs = pki.pairsQuery.data ?? [];

  const create = async (body: CreatePkiPairBody) => {
    const pair = await pki.createMutation.mutateAsync(body);
    setOneTime(pair);
    return pair;
  };

  const download = async (pair: PkiPair) => {
    setDownloadError(null);
    try {
      await downloadPkiBundle(scope, pair);
      pki.invalidate();
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : "下载失败");
    }
  };

  const revoke = (pair: PkiPair) => {
    if (!window.confirm(`吊销 ${pair.name}？已建立的连接不会立即断开。`)) return;
    pki.revokeMutation.mutate(pair.id);
  };

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

      {enabled && <PairStatusCards status={pki.statusQuery.data} pairCount={pairs.length} />}

      <Panel>
        <PanelHead
          title="创建凭证对"
          description="每对包含独立 CA、server 证书和 client 证书；server_name 必须是 DNS 名。"
        />
        <div className="panel-body">
          <CreatePairForm
            isSuper={isSuper}
            currentTenantId={user?.tenant_id ?? null}
            currentTenantLabel={user?.tenant_name ?? user?.tenant_id ?? null}
            tenants={pki.tenantsQuery.data ?? []}
            enabled={enabled}
            pending={pki.createMutation.isPending}
            error={pki.createMutation.error}
            onCreate={create}
          />
          {oneTime && (
            <OneTimeDownload
              pair={oneTime}
              error={downloadError}
              onDownload={() => void download(oneTime)}
            />
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
          <PairTable
            pairs={pairs}
            pending={pki.pairsQuery.isPending}
            error={pki.pairsQuery.error}
            onDownload={(pair) => void download(pair)}
            onRevoke={revoke}
            revokePending={pki.revokeMutation.isPending}
          />
        </div>
      </Panel>
    </div>
  );
}
