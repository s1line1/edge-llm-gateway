// 网关 API 数据类型（与 crates/gateway/src 的 JSON 契约对齐）。

/** 每个 API key 的 token 用量（控制面 key 列表内嵌 + usage）。 */
export interface KeyUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  requests: number;
  /** 其中多少次请求走了估算降级（上游未提供 usage）。 */
  estimated_requests: number;
  /** 最后使用时间（unix 秒；无请求为 0）。 */
  last_used_at: number;
}

/** 控制面 key 列表返回的 key 记录（明文不落盘，prefix 为固定掩码）。 */
export interface ApiKey {
  id: string;
  name: string;
  /** 所属 tenant；旧网关不返回时按 default 展示。 */
  tenant_id?: string;
  tenant_name?: string;
  created_at: number;
  enabled: boolean;
  prefix: string;
  /** 归属的 dashboard 用户；null 表示 tenant 级共享 key。 */
  owner_user_id?: string | null;
  owner_username?: string | null;
  /** 用量汇总（无记录时各字段为 0）。 */
  usage: KeyUsage;
}

/** 控制面 usage 的单条记录（含已吊销 key 的历史，可审计）。 */
export interface UsageRecord {
  key_id: string;
  /** 所属 tenant；旧数据迁入 default。 */
  tenant_id?: string;
  name: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  requests: number;
  estimated_requests: number;
  last_used_at: number;
}

/** POST /{scope}/keys 创建成功时返回（明文 key 仅此一次展示）。 */
export interface CreatedKey extends ApiKey {
  key: string;
}

/** GET /healthz 存活探针。 */
export type HealthStatus = { ok: boolean; text: string };

/**
 * 控制面 agents 的明细（网关已实现，数据来自注册表实时快照）。
 * agent_id / models / max_concurrency / inflight / last_seen 距现在秒数。
 * 前端在 404（旧版网关或未启用 agents 控制面）时优雅降级为仅展示 /metrics 中的在线总数。
 */
export interface AgentInfo {
  agent_id: string;
  /** 所属 tenant；旧网关不返回时按 default 展示。 */
  tenant_id?: string;
  tenant_name?: string;
  /**
   * 来源 IP（已归一、不含端口，如 `"203.0.113.7"` / `"::1"`）。
   *
   * **可选**：本次改动之前的旧网关不返回它，页面必须降级——只显示 `agent_id`，且**不能**
   * 因为它是 `undefined` 就崩，也不能把 `undefined` 渲染成文本。
   *
   * 为什么必须有它：`agent_id` 不再是唯一键——同一个 id 从两个来源 IP 连进来是**两个并存的
   * 节点**（各自独立路由），只有 `ip` 能把它们区分开；同名的多行也因此要靠它做 React key。
   */
  ip?: string;
  models: string[];
  max_concurrency: number;
  /** 当前在途请求数。 */
  inflight: number;
  /** 距上次心跳的秒数（越小越健康）。 */
  last_seen_secs_ago: number;
  /**
   * **是否参与路由**——由网关按它自己配的 `agent_stale_secs` 判定（复扫 G1）。
   *
   * 为什么不让前端自己比：页面顶部用的是网关算出的 `hlmg_agents_healthy`，而表格原先拿一个
   * **写死的 15s** 去比 `last_seen_secs_ago` ⇒ `agent_stale_secs` 一旦不是 15，同一页上
   * "在线总数"与行状态就会自相矛盾。规则只能有一个来源。
   */
  healthy: boolean;
}

/** 从 /metrics 解析出的网关指标快照。 */
export interface MetricsSnapshot {
  fetched_at: number;
  /** 按 HTTP 状态码计数的累计请求数。 */
  requests_by_status: Record<number, number>;
  /** 当前在途请求数（gauge）。 */
  active_requests: number;
  /** 已注册 agent 数（gauge）——**含心跳过期者**（`hlmg_agents` 的 HELP 明说）。 */
  agents: number;
  /** 其中**心跳未过期、真正可路由**的数量（gauge，`hlmg_agents_healthy`）。 */
  agents_healthy: number;
  /** 累计转发给客户端的字节数（counter）。 */
  bytes_out: number;
  /** 累计请求耗时（毫秒，sum）。 */
  request_duration_ms: number;
  /** 累计请求数（sum）。 */
  request_count: number;
}

/** 轮询保留的最近采样点数。 */
export const HISTORY_LEN = 60;

/** dashboard 角色。字符串必须与 Rust `UserRole::as_str` 一致。 */
export type UserRole = "super_admin" | "tenant_admin" | "user";

export interface User {
  id: string | null;
  username: string;
  role: UserRole;
  tenant_id: string | null;
  tenant_name: string | null;
  enabled: boolean;
  created_at: number;
  updated_at: number;
  last_login_at: number;
}

export interface SessionInfo {
  user: User;
  csrf_token: string | null;
  source: "session" | "break_glass";
}

export interface AuthStatus {
  bootstrapped: boolean;
  break_glass_available: boolean;
}

export interface Tenant {
  id: string;
  name: string;
  created_at: number;
  enabled: boolean;
  max_concurrent_requests: number;
  requests_per_minute: number;
  key_count: number;
  user_count: number;
  agent_count: number;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
    requests: number;
  };
  agent_token?: string;
}

export interface AdminUser extends User {
  created_by?: string | null;
}

export interface AuditRecord {
  id: string;
  actor_user_id: string | null;
  actor_label: string;
  tenant_id: string | null;
  action: string;
  target_id: string;
  created_at: number;
}

/** On-demand PKI status (`GET /{scope}/pki/status`). */
export interface PkiStatus {
  enabled: boolean;
  credentials: number;
  tunnel_ready: boolean;
  waiting_for_credentials: boolean;
}

/** A paired server/client credential. The private key is only in the one-time tar. */
export interface PkiPair {
  id: string;
  name: string;
  tenant_id: string;
  server_name: string;
  serial: string;
  ca_fingerprint_sha256: string;
  server_fingerprint_sha256: string;
  client_fingerprint_sha256: string;
  status: "waiting" | "connected" | "revoked" | "expired";
  created_at: number;
  created_by: string;
  downloaded_at: number | null;
  last_connected_at: number | null;
  revoked_at: number | null;
  client_not_after: number;
  download_url: string | null;
}

export interface CreatePkiPairBody {
  name: string;
  tenant_id: string;
  server_name: string;
  server_sans?: string[];
}
