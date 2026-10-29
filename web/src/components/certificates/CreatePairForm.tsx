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
  const [serverName, setServerName] = useState("");
  const [sans, setSans] = useState("");
  const [tenantId, setTenantId] = useState("");

  return (
    <form
      className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"
      onSubmit={async (event) => {
        event.preventDefault();
        try {
          await onCreate({
            name: name.trim(),
            tenant_id: isSuper ? tenantId : (currentTenantId ?? ""),
            server_name: serverName.trim(),
            server_sans: sans
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          });
          setName("");
          setServerName("");
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
      <div className="flex items-end md:col-span-2 xl:col-span-4">
        <Button
          type="submit"
          disabled={
            !enabled || pending || !name.trim() || !serverName.trim() || (isSuper && !tenantId)
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
