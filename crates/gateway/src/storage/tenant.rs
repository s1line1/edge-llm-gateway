//! 租户：身份/配额/agent 归属的持久化模型。
//!
//! 租户是**逻辑边界**，不是独立进程或库：一个 tenant 拥有多个 API key 与多个 edge agent。
//! key 与 agent 的 `tenant_id` 都指向这里；`agent_token_hash` 只给 agent 注册校验用，
//! 没有公开 accessor，永远不进 admin JSON / 日志。

use crate::storage::hash::hex_lower;

pub(crate) const DEFAULT_TENANT_ID: &str = "default";
pub(crate) const DEFAULT_TENANT_NAME: &str = "default";

/// 一条租户记录。`agent_token_hash` 是 `sha256(token)` 的小写十六进制；
/// `default` tenant 的该字段为空，只允许 legacy `Register` 进入。
#[derive(Clone)]
pub struct TenantRecord {
    id: String,
    name: String,
    created_at: u64,
    enabled: bool,
    max_concurrent_requests: u32,
    requests_per_minute: u32,
    agent_token_hash: String,
}

impl TenantRecord {
    pub(crate) fn new(
        id: String,
        name: String,
        created_at: u64,
        enabled: bool,
        max_concurrent_requests: u32,
        requests_per_minute: u32,
        agent_token_hash: String,
    ) -> Self {
        Self {
            id,
            name,
            created_at,
            enabled,
            max_concurrent_requests,
            requests_per_minute,
            agent_token_hash,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn max_concurrent_requests(&self) -> u32 {
        self.max_concurrent_requests
    }

    pub fn requests_per_minute(&self) -> u32 {
        self.requests_per_minute
    }

    /// **crate-only**：只给 storage 做 token 校验，不给 admin/日志。
    pub(crate) fn agent_token_hash(&self) -> &str {
        &self.agent_token_hash
    }
}

/// 新建 tenant 时返回明文 token（仅此一次展示）。
pub struct CreatedTenant {
    pub record: TenantRecord,
    pub agent_token: String,
}

impl std::fmt::Debug for TenantRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("agent_token_hash", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for CreatedTenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedTenant")
            .field("record", &self.record)
            .field("agent_token", &"<redacted>")
            .finish()
    }
}

/// PATCH 语义：`None` = 保持原值；`Some` = 更新。
#[derive(Debug, Clone, Default)]
pub struct TenantPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub max_concurrent_requests: Option<u32>,
    pub requests_per_minute: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    NotFound,
    InvalidName,
    NameTaken,
    HasKeys,
    HasUsers,
    DefaultTenant,
    Disabled,
    BadToken,
    Database(String),
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("tenant not found"),
            Self::InvalidName => f.write_str("tenant name must be 1-64 characters"),
            Self::NameTaken => f.write_str("tenant name already exists"),
            Self::HasKeys => f.write_str("tenant still has API keys"),
            Self::HasUsers => f.write_str("tenant still has users"),
            Self::DefaultTenant => f.write_str("the default tenant cannot be deleted or disabled"),
            Self::Disabled => f.write_str("tenant is disabled"),
            Self::BadToken => f.write_str("invalid tenant agent token"),
            Self::Database(msg) => write!(f, "tenant storage error: {msg}"),
        }
    }
}

impl std::error::Error for TenantError {}

pub(crate) fn default_tenant() -> TenantRecord {
    TenantRecord::new(
        DEFAULT_TENANT_ID.to_string(),
        DEFAULT_TENANT_NAME.to_string(),
        0,
        true,
        0,
        0,
        String::new(),
    )
}

/// 128-bit random tenant id，32 位小写十六进制。
pub(crate) fn generate_tenant_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("os rng");
    hex_lower(&buf)
}

/// 256-bit random agent token，64 位小写十六进制；只把 `sha256(token)` 落库。
pub(crate) fn generate_agent_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("os rng");
    hex_lower(&buf)
}
