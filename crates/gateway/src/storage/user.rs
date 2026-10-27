//! Dashboard 用户与审计记录：角色/租户约束的持久化模型。
//!
//! 密码哈希只在这里进出，记录本身不实现可泄露字段的 `Debug`。用户管理写路径由
//! `storage/mod.rs` 持有；本模块只定义数据形状、校验与角色字符串。

use std::str::FromStr;

use crate::storage::hash::hex_lower;

/// 三种角色。字符串是 API/数据库契约，不能随意改名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    SuperAdmin,
    TenantAdmin,
    User,
}

impl UserRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::TenantAdmin => "tenant_admin",
            Self::User => "user",
        }
    }

    pub fn is_platform(self) -> bool {
        matches!(self, Self::SuperAdmin)
    }
}

impl FromStr for UserRole {
    type Err = UserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "super_admin" => Ok(Self::SuperAdmin),
            "tenant_admin" => Ok(Self::TenantAdmin),
            "user" => Ok(Self::User),
            _ => Err(UserError::InvalidRole),
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一条用户记录。`password_hash` 是 argon2 PHC 串，只给 storage 校验用。
#[derive(Clone)]
pub struct UserRecord {
    id: String,
    tenant_id: Option<String>,
    username: String,
    password_hash: String,
    role: UserRole,
    enabled: bool,
    created_at: u64,
    updated_at: u64,
    last_login_at: u64,
    created_by: Option<String>,
}

impl UserRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        id: String,
        tenant_id: Option<String>,
        username: String,
        password_hash: String,
        role: UserRole,
        enabled: bool,
        created_at: u64,
        updated_at: u64,
        last_login_at: u64,
        created_by: Option<String>,
    ) -> Self {
        Self {
            id,
            tenant_id,
            username,
            password_hash,
            role,
            enabled,
            created_at,
            updated_at,
            last_login_at,
            created_by,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn role(&self) -> UserRole {
        self.role
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    pub fn last_login_at(&self) -> u64 {
        self.last_login_at
    }

    pub fn created_by(&self) -> Option<&str> {
        self.created_by.as_deref()
    }

    pub(crate) fn password_hash(&self) -> &str {
        &self.password_hash
    }
}

impl std::fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRecord")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("username", &self.username)
            .field("password_hash", &"<redacted>")
            .field("role", &self.role)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_login_at", &self.last_login_at)
            .field("created_by", &self.created_by)
            .finish()
    }
}

/// PATCH 语义：`None` = 保持原值。`tenant_id: Some(None)` 表示清空（只对 super_admin 合法）。
#[derive(Debug, Clone, Default)]
pub struct UserPatch {
    pub username: Option<String>,
    pub role: Option<UserRole>,
    pub tenant_id: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub password: Option<String>,
}

/// 新建用户时返回的记录（密码由调用方提供，不在返回值里重复）。
pub struct CreatedUser {
    pub record: UserRecord,
}

/// 审计行：只保存可公开的操作元数据，不保存任何凭据。
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub actor_label: String,
    pub tenant_id: Option<String>,
    pub action: String,
    pub target_id: String,
    pub created_at: u64,
}

impl AuditRecord {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn actor_user_id(&self) -> Option<&str> {
        self.actor_user_id.as_deref()
    }

    pub fn actor_label(&self) -> &str {
        &self.actor_label
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserError {
    NotFound,
    InvalidUsername,
    InvalidPassword,
    UsernameTaken,
    InvalidRole,
    TenantRequired,
    TenantMismatch,
    LastSuperAdmin,
    Disabled,
    Database(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("user not found"),
            Self::InvalidUsername => f.write_str(
                "username must be 3-32 lowercase letters, digits, dot, dash or underscore",
            ),
            Self::InvalidPassword => f.write_str("password must be 12-128 characters"),
            Self::UsernameTaken => f.write_str("username already exists"),
            Self::InvalidRole => f.write_str("invalid role"),
            Self::TenantRequired => f.write_str("tenant is required for this role"),
            Self::TenantMismatch => f.write_str("super_admin must not belong to a tenant"),
            Self::LastSuperAdmin => f.write_str("cannot remove the last enabled super_admin"),
            Self::Disabled => f.write_str("user is disabled"),
            Self::Database(msg) => write!(f, "user storage error: {msg}"),
        }
    }
}

impl std::error::Error for UserError {}

/// 登录用户名规范化：只接受 ASCII 小写/数字/`._-`，首字符必须是字母或数字。
pub fn validate_username(username: &str) -> Result<String, UserError> {
    let normalized = username.trim().to_ascii_lowercase();
    let count = normalized.chars().count();
    if !(3..=32).contains(&count) {
        return Err(UserError::InvalidUsername);
    }
    let mut chars = normalized.chars();
    let first = chars.next().ok_or(UserError::InvalidUsername)?;
    if !first.is_ascii_alphanumeric() {
        return Err(UserError::InvalidUsername);
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(UserError::InvalidUsername);
    }
    Ok(normalized)
}

/// 密码策略：长度 12–128 个字符；不做复杂度规则，避免把弱密码伪装成强密码。
pub fn validate_password(password: &str) -> Result<(), UserError> {
    if !crate::storage::hash::password_length_ok(password) {
        return Err(UserError::InvalidPassword);
    }
    Ok(())
}

/// 生成用户/审计行 id：16 字节随机。
pub fn generate_user_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("os rng");
    hex_lower(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_normalized_and_validated() {
        assert_eq!(validate_username("  Alice.01 ").unwrap(), "alice.01");
        assert_eq!(validate_username("a-b_c").unwrap(), "a-b_c");
        for bad in ["", "ab", "-alice", "alice space", "alice/root", "用户名"] {
            assert!(validate_username(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn password_length_is_enforced() {
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"a".repeat(11)).is_err());
        assert!(validate_password(&"a".repeat(12)).is_ok());
        assert!(validate_password(&"a".repeat(129)).is_err());
    }

    #[test]
    fn password_hash_is_redacted_from_debug() {
        let user = UserRecord::from_parts(
            "u1".into(),
            Some("t1".into()),
            "alice".into(),
            "$argon2id$secret".into(),
            UserRole::User,
            true,
            1,
            1,
            0,
            None,
        );
        let rendered = format!("{user:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("$argon2id$secret"));
    }
}
