// API Keys：签发、查看与吊销调用方凭据。明文只在创建时出现一次。

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";

import { createKey, deleteKey, listKeys } from "../api/client";
import type { CreatedKey, KeyUsage } from "../api/types";
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
import { useAdminToken } from "../hooks/useAdminToken";

export default function Keys() {
  const token = useAdminToken();
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedKey | null>(null);
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState("");

  const keysQuery = useQuery({
    queryKey: ["admin", "keys"],
    queryFn: () => listKeys(token),
    enabled: !!token,
    refetchInterval: 10_000,
  });

  const createMutation = useMutation({
    mutationFn: (keyName: string) => createKey(token, keyName),
    onSuccess: (rec) => {
      setCreated(rec);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["admin", "keys"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteKey(token, id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["admin", "keys"] }),
  });

  const copy = useCallback(async (text: string) => {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        return;
      } catch {
        // Permission denied: fall through to the legacy path.
      }
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) {
        setCopied(true);
        return;
      }
    } catch {
      // Legacy clipboard unavailable: prompt for manual copy.
    }
    window.prompt("复制 API Key（剪贴板不可用，请手动复制）：", text);
  }, []);

  const keys = (keysQuery.data ?? []).filter((k) => {
    const needle = search.trim().toLowerCase();
    if (!needle) return true;
    return `${k.name} ${k.id} ${k.tenant_name ?? k.tenant_id ?? "default"}`
      .toLowerCase()
      .includes(needle);
  });

  return (
    <div className="space-y-6">
      <PageHeader
        index="03"
        eyebrow="CONTROL / CREDENTIALS"
        title="API Keys"
        description="每个客户端一枚独立凭据。Key 持久化在网关 SQLite，只保存 argon2 哈希，明文只在创建时返回一次。"
        actions={
          <>
            <Badge tone="cyan">{keysQuery.data?.length ?? "—"} ISSUED</Badge>
            <IconButton
              icon="refresh"
              label="刷新 Key 列表"
              onClick={() => void keysQuery.refetch()}
            />
          </>
        }
      />

      <div className="grid items-start gap-4 lg:grid-cols-[1.35fr_1fr]">
        <Panel>
          <PanelHead
            eyebrow="ISSUE"
            title="创建新 Key"
            description="为每个客户端（DSH / Codex / 脚本）单独创建，便于独立吊销与计量。"
          />
          <div className="panel-body">
            <form
              className="flex flex-col gap-2 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                if (name.trim()) createMutation.mutate(name.trim());
              }}
            >
              <label className="flex-1">
                <span className="sr-only">Key 用途</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={64}
                  placeholder="用途，如 dsh-client"
                  className="input"
                />
              </label>
              <Button type="submit" disabled={!name.trim() || createMutation.isPending}>
                <Icon name="plus" size={13} />
                {createMutation.isPending ? "创建中…" : "创建 Key"}
              </Button>
            </form>
            {createMutation.isError && (
              <p className="mt-2 font-mono text-[10px] text-coral">
                {createMutation.error.message}
              </p>
            )}

            {created && (
              <div className="mt-4 rounded-lg border border-signal/25 bg-signal/6 p-3">
                <div className="flex items-center gap-2 text-[11px] font-medium text-signal">
                  <Icon name="shield" size={13} />
                  创建成功——明文仅显示这一次：
                </div>
                <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
                  <code className="min-w-0 flex-1 break-all rounded border border-line bg-ink-950/60 px-2.5 py-2 font-mono text-[10px] leading-relaxed text-paper">
                    {created.key}
                  </code>
                  <Button
                    variant="secondary"
                    onClick={() => {
                      void copy(created.key);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                  >
                    <Icon name={copied ? "check" : "copy"} size={12} />
                    {copied ? "已复制" : "复制"}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHead eyebrow="POLICY" title="凭据策略" description="网关不会替你保管明文。" />
          <div className="panel-body space-y-3">
            {[
              ["STORAGE", "SQLite · argon2id hash"],
              ["LOOKUP", "sha256 index · verified cache"],
              ["REVOKE", "immediate · no TTL wait"],
              ["SCOPE", "tenant-scoped routing"],
            ].map(([label, value]) => (
              <div
                key={label}
                className="flex items-start justify-between gap-3 border-b border-line-soft pb-3 last:border-0 last:pb-0"
              >
                <span className="font-mono text-[9px] tracking-[0.1em] text-mist-dim">{label}</span>
                <span className="text-right font-mono text-[10px] text-mist">{value}</span>
              </div>
            ))}
            <p className="pt-1 text-[10px] leading-relaxed text-mist-dim">
              调用方凭据只留在客户端与网关之间，不会随隧道转发到上游模型。
            </p>
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHead
          title="已有 Keys"
          description="吊销立即生效，不可恢复"
          right={
            <label className="flex w-44 items-center gap-2 rounded-md border border-line bg-ink-950/45 px-2.5 py-1.5">
              <Icon name="search" size={12} className="text-mist-dim" />
              <span className="sr-only">搜索 Key</span>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="搜索 name / id"
                className="min-w-0 flex-1 bg-transparent font-mono text-[10px] text-paper outline-none placeholder:text-mist-dim"
              />
            </label>
          }
        />
        <div className="panel-body">
          {deleteMutation.isError && (
            <p className="mb-3 rounded border border-coral/25 bg-coral/6 px-3 py-2 font-mono text-[10px] text-coral">
              吊销失败：{deleteMutation.error.message}（这条 Key 仍然有效）
            </p>
          )}
          {keysQuery.isPending ? (
            <EmptyState title="加载中…" detail="正在读取凭据列表。" />
          ) : keysQuery.isError ? (
            <EmptyState title={`加载失败：${keysQuery.error.message}`} />
          ) : (keysQuery.data ?? []).length === 0 ? (
            <EmptyState
              title="暂无动态 Key，先在上方创建一个"
              detail="创建后把明文配置到客户端的 API key 字段。"
              icon="key"
            />
          ) : keys.length === 0 ? (
            <EmptyState title="没有匹配的 Key" detail="调整搜索词。" icon="search" />
          ) : (
            <div className="-mx-4 overflow-x-auto sm:mx-0">
              <table className="data-table min-w-[860px]">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>Tenant</th>
                    <th>ID</th>
                    <th>前缀</th>
                    <th>用量（token）</th>
                    <th>请求数</th>
                    <th>创建时间</th>
                    <th>状态</th>
                    <th className="text-right">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.id}>
                      <td className="font-medium text-paper">{k.name}</td>
                      <td>
                        <Badge tone="cyan">{k.tenant_name ?? k.tenant_id ?? "default"}</Badge>
                      </td>
                      <td className="font-mono text-[10px] text-mist">{k.id}</td>
                      <td className="font-mono text-[10px] text-mist">{k.prefix}</td>
                      <td className="text-mist">{formatTokens(k.usage)}</td>
                      <td className="font-mono tabular-nums text-mist">{k.usage.requests}</td>
                      <td className="whitespace-nowrap text-[11px] text-mist">
                        {new Date(k.created_at * 1000).toLocaleString()}
                      </td>
                      <td>
                        <Badge tone={k.enabled ? "ok" : "default"}>
                          {k.enabled ? "启用" : "禁用"}
                        </Badge>
                      </td>
                      <td className="text-right">
                        <Button
                          variant="danger"
                          disabled={deleteMutation.isPending}
                          onClick={() => {
                            if (confirm(`吊销 Key「${k.name}」（${k.id}）？立即生效，不可恢复。`)) {
                              deleteMutation.mutate(k.id);
                            }
                          }}
                        >
                          吊销
                        </Button>
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

function formatTokens(u: KeyUsage) {
  if (u.requests === 0) return <span className="text-mist-dim">—</span>;
  const est =
    u.estimated_requests > 0
      ? `（其中 ${u.estimated_requests} 次请求上游未提供 usage，按估算降级）`
      : "";
  return (
    <span
      className="cursor-help"
      title={`prompt ${u.prompt_tokens.toLocaleString()} + completion ${u.completion_tokens.toLocaleString()}${est}`}
    >
      {u.total_tokens.toLocaleString()}
      {u.estimated_requests > 0 && (
        <span className="ml-1 text-amber" title="上游未提供 usage，按估算降级">
          ~
        </span>
      )}
    </span>
  );
}
