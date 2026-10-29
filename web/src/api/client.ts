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
 * 所有 `/admin/*` 请求的统一入口：同源 cookie、禁止缓存、写方法带 CSRF。
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

function adminQuery(tenantId?: string | null): string {
  return tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
}

export async function listKeys(tenantId?: string | null): Promise<ApiKey[]> {
  const resp = await apiFetch(`/admin/keys${adminQuery(tenantId)}`);
  return expectArray<ApiKey>(await handle<unknown>(resp), "GET /admin/keys");
}

export async function createKey(
  name: string,
  tenantId?: string | null,
  ownerUserId?: string | null,
): Promise<CreatedKey> {
  const resp = await apiFetch("/admin/keys", {
    method: "POST",
    body: JSON.stringify({
      name,
      ...(tenantId ? { tenant_id: tenantId } : {}),
      ...(ownerUserId ? { owner_user_id: ownerUserId } : {}),
    }),
  });
  return expectObject<CreatedKey>(await handle<unknown>(resp), "POST /admin/keys");
}

export async function listUsage(tenantId?: string | null): Promise<UsageRecord[]> {
  const resp = await apiFetch(`/admin/usage${adminQuery(tenantId)}`);
  return expectArray<UsageRecord>(await handle<unknown>(resp), "GET /admin/usage");
}

export async function deleteKey(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/keys/${encodeURIComponent(id)}`, { method: "DELETE" });
  await handle<void>(resp);
}

/** Agent 明细；404 仍表示旧版网关或未挂载 /admin/*。 */
export async function fetchAgents(tenantId?: string | null): Promise<AgentInfo[] | null> {
  const resp = await apiFetch(`/admin/agents${adminQuery(tenantId)}`);
  if (resp.status === 404) return null;
  return expectArray<AgentInfo>(await handle<unknown>(resp), "GET /admin/agents");
}

export async function listTenants(): Promise<Tenant[]> {
  const resp = await apiFetch("/admin/tenants");
  return expectArray<Tenant>(await handle<unknown>(resp), "GET /admin/tenants");
}

export async function createTenant(input: {
  name: string;
  max_concurrent_requests?: number;
  requests_per_minute?: number;
}): Promise<Tenant> {
  const resp = await apiFetch("/admin/tenants", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return expectObject<Tenant>(await handle<unknown>(resp), "POST /admin/tenants");
}

export async function updateTenant(
  id: string,
  patch: Partial<
    Pick<Tenant, "name" | "enabled" | "max_concurrent_requests" | "requests_per_minute">
  >,
): Promise<Tenant> {
  const resp = await apiFetch(`/admin/tenants/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return expectObject<Tenant>(await handle<unknown>(resp), "PATCH /admin/tenants");
}

export async function deleteTenant(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/tenants/${encodeURIComponent(id)}`, { method: "DELETE" });
  await handle<void>(resp);
}

export async function rotateAgentToken(id: string): Promise<{ agent_token: string }> {
  const resp = await apiFetch(`/admin/tenants/${encodeURIComponent(id)}/agent-token`, {
    method: "POST",
  });
  return expectObject<{ agent_token: string }>(
    await handle<unknown>(resp),
    "POST /admin/tenants/{id}/agent-token",
  );
}

export async function listUsers(tenantId?: string | null): Promise<AdminUser[]> {
  const resp = await apiFetch(`/admin/users${adminQuery(tenantId)}`);
  return expectArray<AdminUser>(await handle<unknown>(resp), "GET /admin/users");
}

export async function createUser(input: {
  username: string;
  password: string;
  role: UserRole;
  tenant_id?: string | null;
}): Promise<AdminUser> {
  const resp = await apiFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(input),
  });
  return expectObject<AdminUser>(await handle<unknown>(resp), "POST /admin/users");
}

export async function updateUser(
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
  const resp = await apiFetch(`/admin/users/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return expectObject<AdminUser>(await handle<unknown>(resp), "PATCH /admin/users");
}

export async function deleteUser(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/users/${encodeURIComponent(id)}`, { method: "DELETE" });
  await handle<void>(resp);
}

export async function listAudit(tenantId?: string | null): Promise<AuditRecord[]> {
  const resp = await apiFetch(`/admin/audit${adminQuery(tenantId)}`);
  return expectArray<AuditRecord>(await handle<unknown>(resp), "GET /admin/audit");
}

export async function fetchPkiStatus(): Promise<PkiStatus> {
  const resp = await apiFetch("/admin/pki/status");
  return expectObject<PkiStatus>(await handle<unknown>(resp), "GET /admin/pki/status");
}

export async function listPkiPairs(tenantId?: string | null): Promise<PkiPair[]> {
  const resp = await apiFetch(`/admin/pki/pairs${adminQuery(tenantId)}`);
  return expectArray<PkiPair>(await handle<unknown>(resp), "GET /admin/pki/pairs");
}

export async function createPkiPair(body: CreatePkiPairBody): Promise<PkiPair> {
  const resp = await apiFetch("/admin/pki/pairs", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return expectObject<PkiPair>(await handle<unknown>(resp), "POST /admin/pki/pairs");
}

export async function revokePkiPair(id: string): Promise<void> {
  const resp = await apiFetch(`/admin/pki/pairs/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
  });
  await handle<void>(resp);
}

/** Fetch the one-time tar as a blob; the caller creates the download link. */
export async function downloadPkiPair(id: string): Promise<Blob> {
  const resp = await apiFetch(`/admin/pki/pairs/${encodeURIComponent(id)}/download`);
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
