// 网关 HTTP 客户端：同源 session cookie + CSRF，统一错误处理。

import { looksLikePrometheus } from "./metrics";
import type {
  AdminUser,
  AgentInfo,
  ApiKey,
  AuditRecord,
  CreatedKey,
  CreatePkiPairBody,
  HealthStatus,
  PkiPair,
  PkiStatus,
  Tenant,
  UsageRecord,
  UserRole,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function cookieValue(name: string): string {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  const part = document.cookie
    .split(";")
    .map((p) => p.trim())
    .find((p) => p.startsWith(prefix));
  return part ? decodeURIComponent(part.slice(prefix.length)) : "";
}

function isUnsafe(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

/**
 * 控制面请求的统一入口：同源 cookie、禁止缓存、写方法带 CSRF。
 * 会话 token 是 HttpOnly，前端只负责携带 cookie；CSRF 从非 HttpOnly cookie 读取。
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (isUnsafe(init.method ?? "GET")) {
    const csrf = cookieValue("hlmg_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  return fetch(path, {
    ...init,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
}

function expectArray<T>(value: unknown, what: string): T[] {
  if (!Array.isArray(value)) throw new Error(`${what}: 期望数组，收到 ${describe(value)}`);
  return value as T[];
}

function expectObject<T>(value: unknown, what: string): T {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${what}: 期望对象，收到 ${describe(value)}`);
  }
  return value as T;
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

export async function handle<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { error?: { message?: string } };
      if (body.error?.message) message = body.error.message;
    } catch {
      // 非 JSON 响应，保留状态码
    }
    throw new ApiError(resp.status, message);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

/** 网关健康探针（返回纯文本 "ok"）。 */
export async function fetchHealth(): Promise<HealthStatus> {
  try {
    const resp = await fetch("/healthz", { cache: "no-store" });
    return { ok: resp.ok, text: resp.ok ? await resp.text() : `HTTP ${resp.status}` };
  } catch (e) {
    return { ok: false, text: e instanceof Error ? e.message : String(e) };
  }
}

/** `/metrics` 取数的超时（毫秒）。 */
export const METRICS_TIMEOUT_MS = 10_000;

/** 网关 /metrics（Prometheus 文本）。超时防止轮询永久停止。 */
export async function fetchMetricsText(timeoutMs: number = METRICS_TIMEOUT_MS): Promise<string> {
  const resp = await fetch("/metrics", {
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new ApiError(resp.status, `metrics: HTTP ${resp.status}`);
  const text = await resp.text();

  if ((resp.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) {
    throw new Error(
      "metrics: 期望 Prometheus 文本，收到的却是 HTML —— 可能是缓存把 /metrics 的 SPA 页面喂了过来",
    );
  }
  if (!looksLikePrometheus(text)) {
    throw new Error("metrics: 期望 Prometheus 文本，但一行样本都解析不出来");
  }
  return text;
}

export type ApiScope = "account" | "admin" | "system";

/** Map the authenticated role to its control-plane namespace. */
export function scopeForRole(role: UserRole | null | undefined): ApiScope {
  switch (role) {
    case "user":
      return "account";
    case "tenant_admin":
      return "admin";
    case "super_admin":
      return "system";
    default:
      throw new Error(`unknown role: ${String(role)}`);
  }
}

function scopeBase(scope: ApiScope): string {
  return `/${scope}`;
}

function adminQuery(tenantId?: string | null): string {
  return tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
}

export async function listKeys(scope: ApiScope, tenantId?: string | null): Promise<ApiKey[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/keys${adminQuery(tenantId)}`);
  return expectArray<ApiKey>(await handle<unknown>(resp), `GET /${scope}/keys`);
}

export async function createKey(
  scope: ApiScope,
  name: string,
  tenantId?: string | null,
  ownerUserId?: string | null,
): Promise<CreatedKey> {
  const resp = await apiFetch(`${scopeBase(scope)}/keys`, {
    method: "POST",
    body: JSON.stringify({
      name,
      ...(tenantId ? { tenant_id: tenantId } : {}),
      ...(ownerUserId ? { owner_user_id: ownerUserId } : {}),
    }),
  });
  return expectObject<CreatedKey>(await handle<unknown>(resp), `POST /${scope}/keys`);
}

export async function listUsage(scope: ApiScope, tenantId?: string | null): Promise<UsageRecord[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/usage${adminQuery(tenantId)}`);
  return expectArray<UsageRecord>(await handle<unknown>(resp), `GET /${scope}/usage`);
}

export async function deleteKey(scope: ApiScope, id: string): Promise<void> {
  const resp = await apiFetch(`${scopeBase(scope)}/keys/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  await handle<void>(resp);
}

/** Agent 明细；404 表示当前 namespace 未挂载该资源。 */
export async function fetchAgents(
  scope: ApiScope,
  tenantId?: string | null,
): Promise<AgentInfo[] | null> {
  const resp = await apiFetch(`${scopeBase(scope)}/agents${adminQuery(tenantId)}`);
  if (resp.status === 404) return null;
  return expectArray<AgentInfo>(await handle<unknown>(resp), `GET /${scope}/agents`);
}

export async function listTenants(scope: ApiScope): Promise<Tenant[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/tenants`);
  return expectArray<Tenant>(await handle<unknown>(resp), `GET /${scope}/tenants`);
}

export async function createTenant(
  scope: ApiScope,
  input: {
    name: string;
    max_concurrent_requests?: number;
    requests_per_minute?: number;
  },
): Promise<Tenant> {
  const resp = await apiFetch(`${scopeBase(scope)}/tenants`, {
    method: "POST",
    body: JSON.stringify(input),
  });
  return expectObject<Tenant>(await handle<unknown>(resp), `POST /${scope}/tenants`);
}

export async function updateTenant(
  scope: ApiScope,
  id: string,
  patch: Partial<
    Pick<Tenant, "name" | "enabled" | "max_concurrent_requests" | "requests_per_minute">
  >,
): Promise<Tenant> {
  const resp = await apiFetch(`${scopeBase(scope)}/tenants/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return expectObject<Tenant>(await handle<unknown>(resp), `PATCH /${scope}/tenants`);
}

export async function deleteTenant(scope: ApiScope, id: string): Promise<void> {
  const resp = await apiFetch(`${scopeBase(scope)}/tenants/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  await handle<void>(resp);
}

export async function rotateAgentToken(
  scope: ApiScope,
  id: string,
): Promise<{ agent_token: string }> {
  const resp = await apiFetch(`${scopeBase(scope)}/tenants/${encodeURIComponent(id)}/agent-token`, {
    method: "POST",
  });
  return expectObject<{ agent_token: string }>(
    await handle<unknown>(resp),
    `POST /${scope}/tenants/{id}/agent-token`,
  );
}

export async function listUsers(scope: ApiScope, tenantId?: string | null): Promise<AdminUser[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/users${adminQuery(tenantId)}`);
  return expectArray<AdminUser>(await handle<unknown>(resp), `GET /${scope}/users`);
}

export async function createUser(
  scope: ApiScope,
  input: {
    username: string;
    password: string;
    role: UserRole;
    tenant_id?: string | null;
  },
): Promise<AdminUser> {
  const resp = await apiFetch(`${scopeBase(scope)}/users`, {
    method: "POST",
    body: JSON.stringify(input),
  });
  return expectObject<AdminUser>(await handle<unknown>(resp), `POST /${scope}/users`);
}

export async function updateUser(
  scope: ApiScope,
  id: string,
  patch: {
    username?: string;
    password?: string;
    role?: UserRole;
    tenant_id?: string;
    clear_tenant?: boolean;
    enabled?: boolean;
  },
): Promise<AdminUser> {
  const resp = await apiFetch(`${scopeBase(scope)}/users/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return expectObject<AdminUser>(await handle<unknown>(resp), `PATCH /${scope}/users`);
}

export async function deleteUser(scope: ApiScope, id: string): Promise<void> {
  const resp = await apiFetch(`${scopeBase(scope)}/users/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  await handle<void>(resp);
}

export async function listAudit(scope: ApiScope, tenantId?: string | null): Promise<AuditRecord[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/audit${adminQuery(tenantId)}`);
  return expectArray<AuditRecord>(await handle<unknown>(resp), `GET /${scope}/audit`);
}

export async function fetchPkiStatus(scope: ApiScope): Promise<PkiStatus> {
  const resp = await apiFetch(`${scopeBase(scope)}/pki/status`);
  return expectObject<PkiStatus>(await handle<unknown>(resp), `GET /${scope}/pki/status`);
}

export async function listPkiPairs(scope: ApiScope, tenantId?: string | null): Promise<PkiPair[]> {
  const resp = await apiFetch(`${scopeBase(scope)}/pki/pairs${adminQuery(tenantId)}`);
  return expectArray<PkiPair>(await handle<unknown>(resp), `GET /${scope}/pki/pairs`);
}

export async function createPkiPair(scope: ApiScope, body: CreatePkiPairBody): Promise<PkiPair> {
  const resp = await apiFetch(`${scopeBase(scope)}/pki/pairs`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return expectObject<PkiPair>(await handle<unknown>(resp), `POST /${scope}/pki/pairs`);
}

export async function revokePkiPair(scope: ApiScope, id: string): Promise<void> {
  const resp = await apiFetch(`${scopeBase(scope)}/pki/pairs/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
  });
  await handle<void>(resp);
}

/** Fetch the one-time tar as a blob; the caller creates the download link. */
export async function downloadPkiPair(scope: ApiScope, id: string): Promise<Blob> {
  const resp = await apiFetch(`${scopeBase(scope)}/pki/pairs/${encodeURIComponent(id)}/download`);
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { error?: { message?: string } };
      if (body.error?.message) message = body.error.message;
    } catch {
      // keep status
    }
    throw new ApiError(resp.status, message);
  }
  return resp.blob();
}
