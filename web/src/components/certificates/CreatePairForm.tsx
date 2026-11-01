import { useState } from "react";

import type { CreatePkiPairBody, Tenant } from "../../api/types";
import { Icon } from "../icons";
import { Badge, Button, Field } from "../ui";

export function CreatePairForm({
  isSuper,
  currentTenantId,
  currentTenantLabel,
  tenants,
  enabled,
  pending,
  error,
  onCreate,
}: {
  isSuper: boolean;
  currentTenantId: string | null;
  currentTenantLabel: string | null;
  tenants: Tenant[];
  enabled: boolean;
  pending: boolean;
  error: unknown;
  onCreate: (body: CreatePkiPairBody) => Promise<unknown>;
}) {
  const [name, setName] = useState("");
  const [serverSuffix, setServerSuffix] = useState("");
  const [sans, setSans] = useState("");
  const [tenantId, setTenantId] = useState("");
  const selectedTenant = tenants.find((tenant) => tenant.id === tenantId);
  const tenantPrefix =
    (isSuper ? selectedTenant?.name : currentTenantLabel)?.trim().toLowerCase() ?? "";
  const hasTenant = !isSuper || Boolean(tenantId);
  const prefixValid =
    tenantPrefix.length > 0 &&
    tenantPrefix.length <= 63 &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(tenantPrefix);
  const serverName = prefixValid ? `${tenantPrefix}.${serverSuffix.trim()}` : serverSuffix.trim();

  return (
    <form
      className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"
      onSubmit={async (event) => {
        event.preventDefault();
        try {
          await onCreate({
            name: name.trim(),
            tenant_id: isSuper ? tenantId : (currentTenantId ?? ""),
            server_name: serverName,
            server_sans: sans
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          });
          setName("");
          setServerSuffix("");
          setSans("");
        } catch {
          // The mutation error is rendered by the parent.
        }
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
        <div className="flex min-h-10 items-stretch">
          <span className="flex items-center rounded-l-lg border border-r-0 border-line bg-ink-950/50 px-2.5 font-mono text-[11px] text-mist">
            {prefixValid ? `${tenantPrefix}.` : hasTenant ? "invalid" : "选择 tenant"}
          </span>
          <input
            id="pki-server-name"
            className="input rounded-l-none"
            value={serverSuffix}
            onChange={(e) => setServerSuffix(e.target.value)}
            placeholder="gateway.example.com"
            autoComplete="off"
          />
        </div>
        {!hasTenant && (
          <p className="mt-1 text-[10px] text-mist">选择 Tenant 后自动显示固定前缀。</p>
        )}
        {hasTenant && !prefixValid && (
          <p className="mt-1 text-[10px] text-coral">
            当前 tenant 名称无法作为 DNS label；请使用小写字母、数字和连字符。
          </p>
        )}
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
            {tenants.map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        </Field>
      ) : (
        <Field label="Tenant">
          <div className="flex min-h-10 items-center rounded-lg border border-line bg-ink-950/30 px-3">
            <Badge tone="cyan">{currentTenantLabel ?? "current tenant"}</Badge>
          </div>
        </Field>
      )}
      <p className="text-[10px] leading-relaxed text-mist md:col-span-2 xl:col-span-4">
        不同 tenant 必须使用不同 SNI；同一个 server_name 在凭证对吊销前全局唯一。建议使用
        tenant-qualified 名称，例如 <code>tenant-a.gateway.example.com</code>。
      </p>
      <div className="flex items-end md:col-span-2 xl:col-span-4">
        <Button
          type="submit"
          disabled={
            !enabled ||
            pending ||
            !name.trim() ||
            !prefixValid ||
            !serverSuffix.trim() ||
            (isSuper && !tenantId)
          }
        >
          <Icon name="plus" size={13} />
          {pending ? "创建中…" : "创建凭证对"}
        </Button>
        {error != null && (
          <span className="ml-3 text-[10px] text-coral">
            {error instanceof Error ? error.message : "创建失败"}
          </span>
        )}
      </div>
    </form>
  );
}
