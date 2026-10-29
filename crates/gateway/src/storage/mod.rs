//! API Key 存储：所有动态 key 持久化在 SQLite（无静态 key 列表）。
//! key 通过 Admin API 创建/吊销，立即生效，无需重启网关。
//!
//! 安全模型（argon2 哈希存储，不再存明文）：
//! - 明文 key 仅创建时返回一次，此后**只存 argon2 哈希**（PHC 格式）。拖库拿到的
//!   是哈希，不是可用的 key；且默认参数（Argon2id m=19456/t=2/p=1，OWASP 建议）
//!   让离线暴破成本极高。
//! - 授权热路径：`sha256(token)` 作为快速索引（lookup）O(1) 定位记录，再对**单条**
//!   记录做 argon2 校验——避免对每条记录都做昂贵的 argon2 验证。明文 key 是 192 位
//!   随机数，lookup 索引哈希本身不构成泄露；argon2 哈希才是防离线暴破的主体。
//! - 架构：内存索引（runtime HashMap，key=lookup）保证 `authorize()` 热路径零 IO；
//!   SQLite 负责持久化，创建/吊销时写穿（write-through）。
//!
//! 注意：argon2 校验每次约耗时 10-30ms，且**同时占用 19MiB 工作内存**（m=19456）。
//! 早期实现对**每个请求**都完整校验一次，于是内存峰值 ≈ `并发请求数 × 19MiB`
//! （实测：8 并发同 key 请求 → RSS 8.7MB→160.8MB；vmmap 里正好 8 块 19.0MB；
//! 换用无效 key（sha256 未命中、不跑 argon2）则零增长）。云端 2 核/1.6G 上 32 并发
//! 到 654MB 即由此而来，并因此被 OOM 杀掉。
//!
//! 现在走 `verified::VerifiedCache`：**缓存 + 单飞 + 凭据版本校验**——
//! argon2 降到"每(凭据版本)一次"，每请求只做 O(1) 的 enabled/版本核对，
//! 且吊销依然即时生效（版本不一致或记录消失即拒）。`verified_cache_max: 0` 可关闭。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use rusqlite::Connection;

use crate::error::GatewayError;

pub mod hash;
mod pki;
mod session;
mod tenant;
mod usage;
pub mod user;
mod verified;

pub use session::{CreatedSession, SessionRecord};
pub(crate) use tenant::DEFAULT_TENANT_ID;
pub use tenant::{CreatedTenant, TenantError, TenantPatch, TenantRecord};
pub use user::{AuditRecord, CreatedUser, UserError, UserPatch, UserRecord, UserRole};

/// 用量记账/落库的类型由私有模块 `usage` 定义，路径 `crate::storage::UsageDelta` 保持不变。
pub use pki::PkiRecord;
pub use usage::{KeyUsageInfo, UsageDelta};

use crate::storage::hash::{
    constant_time_eq, generate_id_key, hash_argon2, lookup_of, now_secs, verify_argon2,
};
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

mod db;
mod schema;

use schema::{load_keys, load_sessions, load_tenants, load_users};

#[derive(Clone)]
pub struct Storage {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    /// 动态 key，key = lookup（sha256(token) 十六进制），value = 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// 租户；`default` 始终存在。
    tenants: RwLock<HashMap<String, tenant::TenantRecord>>,
    /// dashboard 用户，key = user id。
    users: RwLock<HashMap<String, user::UserRecord>>,
    /// 规范化用户名 → user id；与 `users` 同步维护。
    usernames: RwLock<HashMap<String, String>>,
    /// 服务端会话，key = sha256(token)。
    sessions: RwLock<HashMap<String, session::SessionRecord>>,
    /// SQLite 持久化连接（None = 仅内存，如 db 打开失败时降级）。
    ///
    /// **与用量记账共享**（`Arc`）：连接是**资源**（凭据写穿与用量落库都用它），
    /// 而状态刻意不共享——`runtime` 归凭据、`usage` 归 `usage::UsageStore`。
    db: Arc<Mutex<Option<Connection>>>,
    /// per-key 用量：记账 + 批量落库（独立模块，见 `usage`）。
    usage: usage::UsageStore,
    /// 已验证身份缓存（argon2 结果复用）+ 单飞 + 它自己的容量/有效期策略。
    verified: verified::VerifiedCache,
    /// 凭据代数：**只在凭据相关变更时**自增（创建/吊销/轮换）。
    /// 每条记录带一个 `cred_version`，变更后旧缓存条目的版本对不上 → 立即失效。
    cred_generation: AtomicU64,
    /// 启动期持久化自检：`None` = **没配 `keys_file`**（内存模式）；
    /// `Some(Ok(()))` = 库已就绪；`Some(Err(why))` = 已降级成内存模式，`why` 是原因。
    ///
    /// 库/测试语义：失败仍降级（构造器刻意保持不可失败）。**生产启动路径据此 fail-fast**
    /// ——见 [`Storage::persistence_state`] 与 `Gateway::start`：一个载不出任何 key 的网关
    /// 就是个空壳（每个请求 401），却会一直报健康。
    persistence: Option<Result<(), String>>,
}

/// 一条动态 key 的记录。**凭据字段不出本模块**：`key_hash` 是 argon2 的 PHC 串、
/// `lookup` 是 sha256(明文)，两者都够用来做离线爆破，所以它们（以及内部代数
/// `cred_version`）都是 crate 可见，不对外暴露；外部能看到的只有 [`Self::id`]、
/// [`Self::name`]、[`Self::created_at`]、[`Self::enabled`] —— 与 `/admin/keys` 的
/// 线格式一致。
///
/// 刻意**不实现 `Debug`**：`{:?}` 会把 `key_hash` 打进日志，而记录本身没有任何需要
/// `Debug` 的场景（评估 §7 步骤 6）。
#[derive(Clone)]
pub struct KeyRecord {
    pub(crate) id: String,
    /// argon2 哈希（PHC 格式，如 `$argon2id$v=19$m=19456,t=2,p=1$...`），非明文。
    pub(crate) key_hash: String,
    /// 快速索引：sha256(明文 key) 的十六进制，授权时 O(1) 定位记录。
    pub(crate) lookup: String,
    pub(crate) name: String,
    pub(crate) created_at: u64,
    pub(crate) enabled: bool,
    /// 凭据版本：写入时取当时代数。任何凭据相关变更（吊销/轮换）都会让代数自增，
    /// 从而让基于旧版本建立的已验证缓存**立即失效**（见 `verified` 模块）。
    pub(crate) cred_version: u64,
    pub(crate) tenant_id: String,
    pub(crate) owner_user_id: Option<String>,
}

impl KeyRecord {
    /// key id：对外标识（`/admin/keys`、访问日志、用量表都用它）。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 展示用名字（建 key 时给的，可为空字符串）。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 创建时间（Unix 秒）。
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// 是否启用。注意**吊销**不是靠它：吊销会把记录从 `runtime` 表里删掉（见
    /// [`Storage::delete`]），所以"查得到 + enabled"才代表可用。
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 所属租户 id。
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// 归属的 dashboard 用户；`None` = tenant 级 key（迁移前或管理员创建）。
    pub fn owner_user_id(&self) -> Option<&str> {
        self.owner_user_id.as_deref()
    }
}

/// `create()` 的返回：记录 + 仅此一次的明文 key（之后不再可获取）。
pub struct CreatedKey {
    pub record: KeyRecord,
    pub plaintext: String,
}

/// 已验证身份缓存的默认容量：每条 ~100 字节，1650 条约 165KB。
pub const DEFAULT_VERIFIED_MAX: usize = 1650;
/// 已验证身份的默认有效期。注意：**吊销不依赖它**（版本校验优先），
/// 它只决定"多久之后重新付一次 argon2 的钱"。
const DEFAULT_VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);

/// 写入一条 key 记录；**普通 INSERT**，冲突（id/lookup 重复）交给调用方重试。
///
/// 不能用 `INSERT OR REPLACE`：id 或 lookup 冲突时它会静默删掉另一行（S2-4）。
/// 只把 id/lookup 的 UNIQUE 冲突当作可重试；触发器 ABORT 等其它约束必须原样上报
/// （admin 需要把 `debug: forced insert failure` 这类诊断信息写进日志）。
fn is_unique_key_collision(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, Some(message)) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
                && (message.contains("api_keys.id") || message.contains("api_keys.lookup"))
        }
        _ => false,
    }
}

fn insert_api_key(conn: &Connection, record: &KeyRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled, tenant_id, owner_user_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            record.id,
            record.lookup,
            record.key_hash,
            record.name,
            record.created_at as i64,
            1i64,
            record.tenant_id,
            record.owner_user_id
        ],
    )
    .map(|_| ())
}

fn validate_tenant_name(name: &str) -> Result<String, TenantError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(TenantError::InvalidName);
    }
    Ok(name.to_string())
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl Storage {
    /// 启动期持久化自检的结果：`None` = 没配 `keys_file`；`Some(Ok(()))` = 就绪；
    /// `Some(Err(why))` = 已降级为内存模式（磁盘/权限/损坏/迁移失败…）。
    ///
    /// 为什么单独暴露：构造器**刻意保持不可失败**（库与测试里"内存模式"是合法用法），
    /// 而**生产启动必须 fail-fast**——一个载不出任何 key 的网关是个空壳（每个请求 401），
    /// 却会一直报健康。判据由 [`crate::Gateway::start`] 执行。
    ///
    /// 注意：usage 表的载入失败**不**进入这个结果。它由 `UsageStore` 自己禁用落库
    /// （S2-5），不会因为用量账本读不出来而让一个仍能授权/转发的网关拒绝启动。
    pub fn persistence_state(&self) -> Option<Result<(), String>> {
        self.inner.persistence.clone()
    }

    /// 按 id 取租户快照。
    pub fn tenant(&self, id: &str) -> Option<TenantRecord> {
        read_or_recover(&self.inner.tenants).get(id).cloned()
    }

    /// 全部租户（按 created_at 排序）。
    pub fn tenants(&self) -> Vec<TenantRecord> {
        let mut v: Vec<TenantRecord> = read_or_recover(&self.inner.tenants)
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|t| t.created_at());
        v
    }

    /// key id → tenant id。
    pub fn tenant_of_key(&self, key_id: &str) -> Option<String> {
        read_or_recover(&self.inner.runtime)
            .values()
            .find(|r| r.id == key_id)
            .map(|r| r.tenant_id.clone())
    }

    /// 某 tenant 的当前 key 数（吊销后的 key 不在 runtime 里）。
    pub fn key_count_for_tenant(&self, tenant_id: &str) -> usize {
        read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .count()
    }

    /// 校验 agent 注册 token：tenant 必须存在且启用，token 的 sha256 必须匹配。
    /// `default` 的 hash 为空，因此任何 token 都不匹配（legacy Register 走另一条路）。
    pub(crate) fn verify_agent_token(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<TenantRecord, TenantError> {
        let tenant = self.tenant(tenant_id).ok_or(TenantError::NotFound)?;
        if !tenant.enabled() {
            return Err(TenantError::Disabled);
        }
        let hash = tenant.agent_token_hash();
        if hash.is_empty() || token.is_empty() {
            return Err(TenantError::BadToken);
        }
        if constant_time_eq(lookup_of(token).as_bytes(), hash.as_bytes()) {
            Ok(tenant)
        } else {
            Err(TenantError::BadToken)
        }
    }

    /// 创建 tenant；返回一次性明文 agent token。
    pub fn create_tenant(
        &self,
        name: String,
        max_concurrent_requests: u32,
        requests_per_minute: u32,
    ) -> Result<CreatedTenant, TenantError> {
        let name = validate_tenant_name(&name)?;
        if read_or_recover(&self.inner.tenants)
            .values()
            .any(|t| t.name() == name)
        {
            return Err(TenantError::NameTaken);
        }
        let id = tenant::generate_tenant_id();
        let agent_token = tenant::generate_agent_token();
        let agent_token_hash = lookup_of(&agent_token);
        let record = TenantRecord::new(
            id.clone(),
            name.clone(),
            now_secs(),
            true,
            max_concurrent_requests,
            requests_per_minute,
            agent_token_hash,
        );
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute(
                "INSERT INTO tenants
                 (id, name, created_at, enabled, max_concurrent_requests, requests_per_minute, agent_token_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    record.id(),
                    record.name(),
                    record.created_at() as i64,
                    i64::from(record.enabled()),
                    record.max_concurrent_requests() as i64,
                    record.requests_per_minute() as i64,
                    record.agent_token_hash(),
                ],
            ) {
                if is_unique_violation(&e) {
                    return Err(TenantError::NameTaken);
                }
                return Err(TenantError::Database(e.to_string()));
            }
        }
        write_or_recover(&self.inner.tenants).insert(id, record.clone());
        Ok(CreatedTenant {
            record,
            agent_token,
        })
    }

    /// 更新 tenant；id/name 之外的字段可改。`default` 不能禁用或改名。
    pub fn update_tenant(&self, id: &str, patch: TenantPatch) -> Result<TenantRecord, TenantError> {
        let mut record = self.tenant(id).ok_or(TenantError::NotFound)?;
        if id == tenant::DEFAULT_TENANT_ID {
            if patch.enabled == Some(false) {
                return Err(TenantError::DefaultTenant);
            }
            if let Some(name) = &patch.name {
                if name != record.name() {
                    return Err(TenantError::DefaultTenant);
                }
            }
        }
        let name = match patch.name {
            Some(name) => validate_tenant_name(&name)?,
            None => record.name().to_string(),
        };
        if name != record.name()
            && read_or_recover(&self.inner.tenants)
                .values()
                .any(|t| t.id() != id && t.name() == name)
        {
            return Err(TenantError::NameTaken);
        }
        let enabled = patch.enabled.unwrap_or(record.enabled());
        let max = patch
            .max_concurrent_requests
            .unwrap_or(record.max_concurrent_requests());
        let rpm = patch
            .requests_per_minute
            .unwrap_or(record.requests_per_minute());
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute(
                "UPDATE tenants SET name = ?1, enabled = ?2, max_concurrent_requests = ?3, requests_per_minute = ?4 WHERE id = ?5",
                rusqlite::params![name, i64::from(enabled), max as i64, rpm as i64, id],
            ) {
                return Err(TenantError::Database(e.to_string()));
            }
        }
        record = TenantRecord::new(
            record.id().to_string(),
            name,
            record.created_at(),
            enabled,
            max,
            rpm,
            record.agent_token_hash().to_string(),
        );
        write_or_recover(&self.inner.tenants).insert(id.to_string(), record.clone());
        Ok(record)
    }

    /// 删除 tenant：`default` 与仍有 key 的 tenant 拒绝；agent 存在性由 admin 层检查。
    pub fn delete_tenant(&self, id: &str) -> Result<(), TenantError> {
        if id == tenant::DEFAULT_TENANT_ID {
            return Err(TenantError::DefaultTenant);
        }
        if self.tenant(id).is_none() {
            return Err(TenantError::NotFound);
        }
        if self.key_count_for_tenant(id) > 0 {
            return Err(TenantError::HasKeys);
        }
        if self.user_count_for_tenant(id) > 0 {
            return Err(TenantError::HasUsers);
        }
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute("DELETE FROM tenants WHERE id = ?1", rusqlite::params![id])
            {
                return Err(TenantError::Database(e.to_string()));
            }
        }
        write_or_recover(&self.inner.tenants).remove(id);
        Ok(())
    }

    /// 重新生成 tenant agent token；返回一次性明文。`default` 也允许（显式启用 token 注册）。
    pub fn rotate_agent_token(&self, id: &str) -> Result<String, TenantError> {
        let mut record = self.tenant(id).ok_or(TenantError::NotFound)?;
        let token = tenant::generate_agent_token();
        let hash = lookup_of(&token);
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute(
                "UPDATE tenants SET agent_token_hash = ?1 WHERE id = ?2",
                rusqlite::params![hash, id],
            ) {
                return Err(TenantError::Database(e.to_string()));
            }
        }
        record = TenantRecord::new(
            record.id().to_string(),
            record.name().to_string(),
            record.created_at(),
            record.enabled(),
            record.max_concurrent_requests(),
            record.requests_per_minute(),
            hash,
        );
        write_or_recover(&self.inner.tenants).insert(id.to_string(), record);
        Ok(token)
    }

    /// tenant 的每 key 用量。
    pub fn usage_for_tenant(&self, tenant_id: &str) -> Vec<KeyUsageInfo> {
        self.inner.usage.usage_for_tenant(tenant_id)
    }

    /// 某用户拥有的 key 的用量（按 key id 排序，供普通用户视图）。
    pub fn usage_for_owner(&self, tenant_id: &str, owner_user_id: &str) -> Vec<KeyUsageInfo> {
        let ids: Vec<String> = self
            .list_for_owner(tenant_id, owner_user_id)
            .into_iter()
            .map(|k| k.id().to_string())
            .collect();
        let mut rows: Vec<KeyUsageInfo> = ids.iter().filter_map(|id| self.usage_of(id)).collect();
        rows.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        rows
    }

    /// tenant 汇总 (prompt, completion, total, requests)。
    pub fn tenant_totals(&self, tenant_id: &str) -> (u64, u64, u64, u64) {
        self.inner.usage.tenant_totals(tenant_id)
    }

    // ── dashboard users ──────────────────────────────────────────────────────

    /// 按 id 取用户快照。
    pub fn user(&self, id: &str) -> Option<UserRecord> {
        read_or_recover(&self.inner.users).get(id).cloned()
    }

    /// 按规范化用户名取用户快照。
    pub fn user_by_username(&self, username: &str) -> Option<UserRecord> {
        let username = username.trim().to_ascii_lowercase();
        let users = read_or_recover(&self.inner.users);
        let usernames = read_or_recover(&self.inner.usernames);
        usernames
            .get(&username)
            .and_then(|id| users.get(id))
            .cloned()
            .or_else(|| {
                users
                    .values()
                    .find(|u| u.username().eq_ignore_ascii_case(&username))
                    .cloned()
            })
    }

    /// 全部用户（按创建时间排序）。
    pub fn users(&self) -> Vec<UserRecord> {
        let mut v: Vec<UserRecord> = read_or_recover(&self.inner.users)
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|u| u.created_at());
        v
    }

    /// 某 tenant 的用户（按创建时间排序）。
    pub fn users_for_tenant(&self, tenant_id: &str) -> Vec<UserRecord> {
        let mut v: Vec<UserRecord> = read_or_recover(&self.inner.users)
            .values()
            .filter(|u| u.tenant_id() == Some(tenant_id))
            .cloned()
            .collect();
        v.sort_by_key(|u| u.created_at());
        v
    }

    pub fn user_count(&self) -> usize {
        read_or_recover(&self.inner.users).len()
    }

    pub fn user_count_for_tenant(&self, tenant_id: &str) -> usize {
        read_or_recover(&self.inner.users)
            .values()
            .filter(|u| u.tenant_id() == Some(tenant_id))
            .count()
    }

    /// 创建 dashboard 用户。密码只以 argon2 哈希落库。
    pub fn create_user(
        &self,
        username: String,
        password: String,
        role: UserRole,
        tenant_id: Option<String>,
        created_by: Option<String>,
    ) -> Result<CreatedUser, UserError> {
        let username = user::validate_username(&username)?;
        user::validate_password(&password)?;
        self.ensure_role_tenant(role, tenant_id.as_deref())?;
        if read_or_recover(&self.inner.usernames).contains_key(&username) {
            return Err(UserError::UsernameTaken);
        }
        let password_hash = hash_argon2(&password);
        let now = now_secs();
        let record = UserRecord::from_parts(
            user::generate_user_id(),
            tenant_id,
            username.clone(),
            password_hash,
            role,
            true,
            now,
            now,
            0,
            created_by,
        );
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute(
                "INSERT INTO users
                 (id, tenant_id, username, password_hash, role, enabled, created_at, updated_at, last_login_at, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    record.id(),
                    record.tenant_id(),
                    record.username(),
                    record.password_hash(),
                    record.role().as_str(),
                    i64::from(record.enabled()),
                    record.created_at() as i64,
                    record.updated_at() as i64,
                    record.last_login_at() as i64,
                    record.created_by(),
                ],
            ) {
                if is_unique_violation(&e) {
                    return Err(UserError::UsernameTaken);
                }
                return Err(UserError::Database(e.to_string()));
            }
        }
        write_or_recover(&self.inner.usernames).insert(username, record.id().to_string());
        write_or_recover(&self.inner.users).insert(record.id().to_string(), record.clone());
        Ok(CreatedUser { record })
    }

    /// 更新用户。`password` 在 PATCH 里单独处理（先哈希，再与字段更新一起落库）。
    pub fn update_user(&self, id: &str, patch: UserPatch) -> Result<UserRecord, UserError> {
        let current = self.user(id).ok_or(UserError::NotFound)?;
        let username = match patch.username {
            Some(name) => user::validate_username(&name)?,
            None => current.username().to_string(),
        };
        if username != current.username() {
            let taken = read_or_recover(&self.inner.usernames)
                .get(&username)
                .is_some_and(|other| other != id);
            if taken {
                return Err(UserError::UsernameTaken);
            }
        }
        let role = patch.role.unwrap_or(current.role());
        let tenant = patch
            .tenant_id
            .unwrap_or_else(|| current.tenant_id().map(str::to_string));
        self.ensure_role_tenant(role, tenant.as_deref())?;
        let enabled = patch.enabled.unwrap_or(current.enabled());
        if !enabled && current.role() == UserRole::SuperAdmin && current.enabled() {
            self.ensure_not_last_super(id)?;
        }
        if role != UserRole::SuperAdmin && current.role() == UserRole::SuperAdmin {
            self.ensure_not_last_super(id)?;
        }
        if patch.password.is_some() {
            user::validate_password(patch.password.as_deref().unwrap_or_default())?;
        }
        let password_hash = patch
            .password
            .as_deref()
            .map(hash_argon2)
            .unwrap_or_else(|| current.password_hash().to_string());
        let now = now_secs();
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            if let Err(e) = conn.execute(
                "UPDATE users SET tenant_id = ?1, username = ?2, password_hash = ?3,
                 role = ?4, enabled = ?5, updated_at = ?6 WHERE id = ?7",
                rusqlite::params![
                    tenant.as_deref(),
                    username,
                    password_hash,
                    role.as_str(),
                    i64::from(enabled),
                    now as i64,
                    id,
                ],
            ) {
                if is_unique_violation(&e) {
                    return Err(UserError::UsernameTaken);
                }
                return Err(UserError::Database(e.to_string()));
            }
        }
        let updated = UserRecord::from_parts(
            current.id().to_string(),
            tenant.clone(),
            username.clone(),
            password_hash,
            role,
            enabled,
            current.created_at(),
            now,
            current.last_login_at(),
            current.created_by().map(str::to_string),
        );
        {
            let mut usernames = write_or_recover(&self.inner.usernames);
            usernames.retain(|_, v| v != id);
            usernames.insert(username, id.to_string());
        }
        write_or_recover(&self.inner.users).insert(id.to_string(), updated.clone());
        if !enabled
            || role != current.role()
            || tenant.as_deref() != current.tenant_id()
            || patch.password.is_some()
        {
            let _ = self.revoke_user_sessions(id, None);
        }
        if !enabled {
            let _ = self.disable_keys_for_owner(id);
        }
        Ok(updated)
    }

    /// 删除用户；禁止删除自己由 admin 层检查。最后一个 super_admin 不可删除。
    pub fn delete_user(&self, id: &str) -> Result<(), UserError> {
        let current = self.user(id).ok_or(UserError::NotFound)?;
        if current.role() == UserRole::SuperAdmin {
            self.ensure_not_last_super(id)?;
        }
        let _ = self.revoke_user_sessions(id, None);
        let _ = self.disable_keys_for_owner(id);
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute("DELETE FROM users WHERE id = ?1", rusqlite::params![id])
                .map_err(|e| UserError::Database(e.to_string()))?;
        }
        write_or_recover(&self.inner.usernames).retain(|_, v| v != id);
        write_or_recover(&self.inner.users).remove(id);
        Ok(())
    }

    /// 设置密码并撤销该用户的全部 session（可选保留当前 session hash）。
    pub fn set_user_password(
        &self,
        id: &str,
        password: &str,
        keep_session_hash: Option<&str>,
    ) -> Result<(), UserError> {
        user::validate_password(password)?;
        let current = self.user(id).ok_or(UserError::NotFound)?;
        let hash = hash_argon2(password);
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![hash, now_secs() as i64, id],
            )
            .map_err(|e| UserError::Database(e.to_string()))?;
        }
        let mut users = write_or_recover(&self.inner.users);
        if let Some(user) = users.get_mut(id) {
            *user = UserRecord::from_parts(
                current.id().to_string(),
                current.tenant_id().map(str::to_string),
                current.username().to_string(),
                hash,
                current.role(),
                current.enabled(),
                current.created_at(),
                now_secs(),
                current.last_login_at(),
                current.created_by().map(str::to_string),
            );
        }
        drop(users);
        self.revoke_user_sessions(id, keep_session_hash);
        Ok(())
    }

    /// 校验密码；用户不存在时也执行一次 dummy argon2。
    pub fn verify_password(&self, user: Option<&UserRecord>, password: &str) -> bool {
        hash::verify_login_password(password, user.map(|u| u.password_hash()))
    }

    /// 记录一次成功登录时间。
    pub fn record_login(&self, id: &str) {
        let now = now_secs();
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            let _ = conn.execute(
                "UPDATE users SET last_login_at = ?1, updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now as i64, id],
            );
        }
        if let Some(user) = write_or_recover(&self.inner.users).get_mut(id) {
            *user = UserRecord::from_parts(
                user.id().to_string(),
                user.tenant_id().map(str::to_string),
                user.username().to_string(),
                user.password_hash().to_string(),
                user.role(),
                user.enabled(),
                user.created_at(),
                now,
                now,
                user.created_by().map(str::to_string),
            );
        }
    }

    fn ensure_role_tenant(&self, role: UserRole, tenant_id: Option<&str>) -> Result<(), UserError> {
        match (role, tenant_id) {
            (UserRole::SuperAdmin, None) => Ok(()),
            (UserRole::SuperAdmin, Some(_)) => Err(UserError::TenantMismatch),
            (UserRole::TenantAdmin | UserRole::User, None) => Err(UserError::TenantRequired),
            (UserRole::TenantAdmin | UserRole::User, Some(tenant_id)) => {
                if self.tenant(tenant_id).is_some() {
                    Ok(())
                } else {
                    Err(UserError::TenantRequired)
                }
            }
        }
    }

    fn ensure_not_last_super(&self, target_id: &str) -> Result<(), UserError> {
        let users = read_or_recover(&self.inner.users);
        let target_is_enabled_super = users
            .get(target_id)
            .is_some_and(|u| u.role() == UserRole::SuperAdmin && u.enabled());
        let enabled = users
            .values()
            .filter(|u| u.role() == UserRole::SuperAdmin && u.enabled())
            .count();
        if target_is_enabled_super && enabled <= 1 {
            return Err(UserError::LastSuperAdmin);
        }
        Ok(())
    }

    // ── sessions ─────────────────────────────────────────────────────────────

    pub fn create_session(
        &self,
        user_id: &str,
        ttl_secs: u64,
    ) -> Result<CreatedSession, UserError> {
        let user = self.user(user_id).ok_or(UserError::NotFound)?;
        if !user.enabled() {
            return Err(UserError::Disabled);
        }
        let now = now_secs();
        let token = session::generate_session_token();
        let csrf_token = session::generate_csrf_token();
        let record = SessionRecord::from_parts(
            session::generate_session_id(),
            user_id.to_string(),
            session::session_token_hash(&token),
            now,
            now.saturating_add(ttl_secs.max(1)),
        );
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute(
                "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    record.id(),
                    record.user_id(),
                    record.token_hash(),
                    record.created_at() as i64,
                    record.expires_at() as i64,
                ],
            )
            .map_err(|e| UserError::Database(e.to_string()))?;
        }
        write_or_recover(&self.inner.sessions)
            .insert(record.token_hash().to_string(), record.clone());
        Ok(CreatedSession {
            record,
            token,
            csrf_token,
        })
    }

    /// 校验 session cookie：token hash 命中、未过期、用户与 tenant 都启用。
    pub fn authorize_session(&self, token: &str) -> Option<UserRecord> {
        let hash = session::session_token_hash(token);
        let session = read_or_recover(&self.inner.sessions).get(&hash).cloned()?;
        if session.expires_at() <= now_secs() {
            return None;
        }
        let user = self.user(session.user_id())?;
        if !user.enabled() {
            return None;
        }
        if let Some(tenant_id) = user.tenant_id() {
            if !self.tenant(tenant_id).is_some_and(|t| t.enabled()) {
                return None;
            }
        }
        Some(user)
    }

    pub fn revoke_session(&self, token: &str) -> bool {
        let hash = session::session_token_hash(token);
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            let _ = conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                rusqlite::params![hash],
            );
        }
        write_or_recover(&self.inner.sessions)
            .remove(&hash)
            .is_some()
    }

    /// 撤销用户全部 session；`keep_hash` 可选保留当前 session。
    pub fn revoke_user_sessions(&self, user_id: &str, keep_hash: Option<&str>) -> usize {
        let hashes: Vec<String> = read_or_recover(&self.inner.sessions)
            .iter()
            .filter(|(hash, s)| s.user_id() == user_id && Some(hash.as_str()) != keep_hash)
            .map(|(hash, _)| hash.clone())
            .collect();
        if hashes.is_empty() {
            return 0;
        }
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            for hash in &hashes {
                let _ = conn.execute(
                    "DELETE FROM sessions WHERE token_hash = ?1",
                    rusqlite::params![hash],
                );
            }
        }
        let mut sessions = write_or_recover(&self.inner.sessions);
        for hash in &hashes {
            sessions.remove(hash);
        }
        hashes.len()
    }

    pub fn prune_expired_sessions(&self, now: u64) -> usize {
        let hashes: Vec<String> = read_or_recover(&self.inner.sessions)
            .iter()
            .filter(|(_, s)| s.expires_at() <= now)
            .map(|(hash, _)| hash.clone())
            .collect();
        if hashes.is_empty() {
            return 0;
        }
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            for hash in &hashes {
                let _ = conn.execute(
                    "DELETE FROM sessions WHERE token_hash = ?1",
                    rusqlite::params![hash],
                );
            }
        }
        let mut sessions = write_or_recover(&self.inner.sessions);
        for hash in &hashes {
            sessions.remove(hash);
        }
        hashes.len()
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        read_or_recover(&self.inner.sessions).len()
    }

    // ── audit ────────────────────────────────────────────────────────────────

    pub fn append_audit(
        &self,
        actor_user_id: Option<&str>,
        actor_label: &str,
        tenant_id: Option<&str>,
        action: &str,
        target_id: &str,
    ) -> Result<(), GatewayError> {
        let record = AuditRecord {
            id: user::generate_user_id(),
            actor_user_id: actor_user_id.map(str::to_string),
            actor_label: actor_label.to_string(),
            tenant_id: tenant_id.map(str::to_string),
            action: action.to_string(),
            target_id: target_id.to_string(),
            created_at: now_secs(),
        };
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute(
                "INSERT INTO admin_audit
                 (id, actor_user_id, actor_label, tenant_id, action, target_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    record.id,
                    record.actor_user_id,
                    record.actor_label,
                    record.tenant_id,
                    record.action,
                    record.target_id,
                    record.created_at as i64,
                ],
            )?;
        }
        Ok(())
    }

    pub fn audit_records(&self, tenant_id: Option<&str>, limit: usize) -> Vec<AuditRecord> {
        let conn = lock_or_recover(&self.inner.db);
        let Some(conn) = conn.as_ref() else {
            return Vec::new();
        };
        let sql = if tenant_id.is_some() {
            "SELECT id, actor_user_id, actor_label, tenant_id, action, target_id, created_at
             FROM admin_audit WHERE tenant_id = ?1 ORDER BY created_at DESC LIMIT ?2"
        } else {
            "SELECT id, actor_user_id, actor_label, tenant_id, action, target_id, created_at
             FROM admin_audit ORDER BY created_at DESC LIMIT ?1"
        };
        let mut out = Vec::new();
        let map = |r: &rusqlite::Row<'_>| {
            Ok(AuditRecord {
                id: r.get(0)?,
                actor_user_id: r.get(1)?,
                actor_label: r.get(2)?,
                tenant_id: r.get(3)?,
                action: r.get(4)?,
                target_id: r.get(5)?,
                created_at: r.get::<_, i64>(6)? as u64,
            })
        };
        if let Some(tid) = tenant_id {
            if let Ok(mut stmt) = conn.prepare(sql) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![tid, limit as i64], map) {
                    out.extend(rows.flatten());
                }
            }
        } else if let Ok(mut stmt) = conn.prepare(sql) {
            if let Ok(rows) = stmt.query_map(rusqlite::params![limit as i64], map) {
                out.extend(rows.flatten());
            }
        }
        out
    }

    pub fn new(file: Option<PathBuf>) -> Self {
        Self::with_verified(file, DEFAULT_VERIFIED_MAX, DEFAULT_VERIFIED_TTL)
    }

    pub fn default_verified_ttl() -> Duration {
        DEFAULT_VERIFIED_TTL
    }

    pub fn default_verified_max() -> usize {
        DEFAULT_VERIFIED_MAX
    }

    /// 指定已验证缓存容量与有效期；`max = 0` 关闭缓存（恢复"每请求都跑 argon2"的旧行为）。
    ///
    /// 默认（[`Self::new`]）：1650 条缓存、30 分钟有效期——够覆盖"同一批客户端持续打"的场景；
    /// **吊销不依赖它**（版本/记录消失的校验在缓存之前），TTL 只决定"多久之后重新付一次
    /// argon2 的钱"。
    pub fn with_verified(file: Option<PathBuf>, max: usize, ttl: Duration) -> Self {
        // 打开/收紧/建表/迁移都在 `db::open` 里；这里只把结果装进 `Storage`。
        let opened = db::open(file.as_deref());
        let mut persistence = opened.persistence;
        let db = opened.conn;
        let runtime = match &db {
            Some(conn) => match load_keys(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("keys db load failed: {e}; using empty store");
                    if matches!(persistence, Some(Ok(()))) {
                        persistence = Some(Err(format!("cannot load the keys db: {e}")));
                    }
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        // 连接是**资源**：凭据写穿与用量落库共用它，因此包一层 `Arc`；
        // 而状态各自独占——`runtime` 留在这里，用量账本交给 `usage::UsageStore`
        //（它在构造时自己从 `key_usage` 载入，失败只告警并按空账本继续）。
        let mut tenants = match &db {
            Some(conn) => match load_tenants(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("tenants db load failed: {e}; using only the default tenant");
                    if matches!(persistence, Some(Ok(()))) {
                        persistence = Some(Err(format!("cannot load the tenants db: {e}")));
                    }
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        tenants
            .entry(tenant::DEFAULT_TENANT_ID.to_string())
            .or_insert_with(tenant::default_tenant);
        let (users, sessions) = match &db {
            Some(conn) => {
                let users = match load_users(conn) {
                    Ok(map) => map,
                    Err(e) => {
                        tracing::warn!("users db load failed: {e}; using empty user store");
                        if matches!(persistence, Some(Ok(()))) {
                            persistence = Some(Err(format!("cannot load the users db: {e}")));
                        }
                        HashMap::new()
                    }
                };
                let now = now_secs();
                let sessions = match load_sessions(conn) {
                    Ok(map) => map
                        .into_iter()
                        .filter(|(_, s)| s.expires_at() > now)
                        .collect::<HashMap<_, _>>(),
                    Err(e) => {
                        tracing::warn!("sessions db load failed: {e}; using empty session store");
                        if matches!(persistence, Some(Ok(()))) {
                            persistence = Some(Err(format!("cannot load the sessions db: {e}")));
                        }
                        HashMap::new()
                    }
                };
                (users, sessions)
            }
            None => (HashMap::new(), HashMap::new()),
        };
        let mut usernames = HashMap::new();
        for user in users.values() {
            usernames.insert(user.username().to_ascii_lowercase(), user.id().to_string());
        }
        let db = Arc::new(Mutex::new(db));
        let usage = usage::UsageStore::new(db.clone());
        let storage = Self {
            inner: Arc::new(StoreInner {
                runtime: RwLock::new(runtime),
                tenants: RwLock::new(tenants),
                users: RwLock::new(users),
                usernames: RwLock::new(usernames),
                sessions: RwLock::new(sessions),
                db,
                usage,
                verified: verified::VerifiedCache::new(max, ttl),
                cred_generation: AtomicU64::new(1),
                persistence,
            }),
        };
        storage.prune_expired_sessions(now_secs());
        storage
    }

    /// 推进凭据代数并返回新值。**任何**改变"某个 key 是否有效/其哈希"的写路径
    /// 都必须调用它，否则已验证缓存会继续放行旧身份（见 `verified` 模块的安全性说明）。
    fn bump_cred_generation(&self) -> u64 {
        self.inner
            .cred_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    /// 校验 token 是否为启用中的动态 key（sha256 定位 + argon2 校验）。
    ///
    /// 生产路径走 [`Self::authorize_record`]（`auth.rs` 需要 id 与 name）；这个布尔形态
    /// 是给 **benches 与库调用方**的便利入口，网关自身不调用它。
    pub fn authorize(&self, token: &str) -> bool {
        self.authorize_record(token).is_some()
    }

    /// 校验并返回 key 记录。
    ///
    /// **协议不在这里**：快路径 → 单飞 → 双检 → 校验 → 写缓存全在
    /// `verified::VerifiedCache::verify_or_cached` 里，本函数只提供两个动作——
    /// "按 lookup 取当前记录"（读 `runtime`）与"真跑一次 argon2"。
    ///
    /// 热路径（有缓存时）只做三件事：`sha256(token)` → O(1) 查表 → 比对凭据版本，
    /// **不跑 argon2**；只有缓存未命中（首次见到该 token、版本变了、或缓存关闭）才校验。
    ///
    /// 记录以**值**交给协议（`load_record` 里 `.cloned()`），于是 `runtime` 的读锁在 argon2
    /// 之前就放开了：建/吊销（写锁）不会再被一次 10–30ms 的冷校验堵住（评估 §5 N1）。
    /// 这不是"记得 drop"，是接口形状决定的——闭包没法把守卫借出去。
    pub fn authorize_record(&self, token: &str) -> Option<KeyRecord> {
        let lookup = lookup_of(token);
        self.inner.verified.verify_or_cached(
            &lookup,
            || read_or_recover(&self.inner.runtime).get(&lookup).cloned(),
            |rec| verify_argon2(token, &rec.key_hash),
        )
    }

    /// (缓存命中, 未命中/校验次数)：供 `/metrics` 观察 argon2 复用情况。
    pub fn verified_counters(&self) -> (u64, u64) {
        self.inner.verified.counters()
    }

    /// 创建动态 key 并持久化；返回记录与仅此一次的明文 key。
    ///
    /// **顺序是"先落库、后进内存"**：落库失败就返回 `Err`，内存与库都不变——否则会出现
    /// "管理页显示一把重启后就消失的 key"（评估 §5 H2 / 记录 P2-9），而且那把 key 的明文
    /// 已经交给了调用方，收不回来。
    ///
    /// 纯内存模式（`db = None`，库打不开时的降级）没有可落库的对象，直接成功。
    pub fn create(&self, name: String) -> Result<CreatedKey, GatewayError> {
        self.create_in(tenant::DEFAULT_TENANT_ID, None, name)
    }

    /// 在指定 tenant 下创建 key。tenant 必须存在且启用；`owner_user_id` 必须是同 tenant 用户。
    pub fn create_in(
        &self,
        tenant_id: &str,
        owner_user_id: Option<&str>,
        name: String,
    ) -> Result<CreatedKey, GatewayError> {
        if let Some(t) = self.tenant(tenant_id) {
            if !t.enabled() {
                return Err(GatewayError::Other("tenant is disabled".into()));
            }
        } else {
            return Err(GatewayError::Other("tenant not found".into()));
        }
        if let Some(owner) = owner_user_id {
            let Some(user) = self.user(owner) else {
                return Err(GatewayError::Other("key owner not found".into()));
            };
            if user.tenant_id() != Some(tenant_id) {
                return Err(GatewayError::Other(
                    "key owner must belong to the same tenant".into(),
                ));
            }
        }
        for _ in 0..3 {
            let (id, plaintext) = generate_id_key();
            let lookup = lookup_of(&plaintext);
            let key_hash = hash_argon2(&plaintext);
            let mut record = KeyRecord {
                id,
                key_hash,
                lookup,
                name: name.clone(),
                created_at: now_secs(),
                enabled: true,
                // 成功落库后才 bump；重试不能浪费凭据代数。
                cred_version: 0,
                tenant_id: tenant_id.to_string(),
                owner_user_id: owner_user_id.map(str::to_string),
            };
            // ① 先落库。失败 → 直接把错误交给调用方（admin 映射 500），内存一个字都不改。
            if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
                match insert_api_key(conn, &record) {
                    Ok(()) => {}
                    Err(e) if is_unique_key_collision(&e) => {
                        // id 或 lookup 撞了：换一组随机值重试，绝不能 REPLACE 掉已有行。
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            record.cred_version = self.bump_cred_generation();
            // ② 再进内存：此后授权立即可用。
            write_or_recover(&self.inner.runtime).insert(record.lookup.clone(), record.clone());
            tracing::info!(id = %record.id, name = %record.name, "api key created");
            return Ok(CreatedKey { record, plaintext });
        }
        Err(GatewayError::Other(
            "could not allocate a unique key id".into(),
        ))
    }

    /// 列出动态 key（不含明文；由调用方决定展示形式）。
    pub fn list(&self) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 只列指定 tenant 的 key。
    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 按 id 取 key 快照（权限检查用；不暴露哈希）。
    pub fn key(&self, id: &str) -> Option<KeyRecord> {
        read_or_recover(&self.inner.runtime)
            .values()
            .find(|r| r.id == id)
            .cloned()
    }

    /// 只列某用户拥有的 key。
    pub fn list_for_owner(&self, tenant_id: &str, owner_user_id: &str) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| {
                r.tenant_id == tenant_id && r.owner_user_id.as_deref() == Some(owner_user_id)
            })
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 停用某用户拥有的全部 key（禁用/删除用户时调用）。返回实际停用条数。
    pub fn disable_keys_for_owner(&self, owner_user_id: &str) -> Result<usize, GatewayError> {
        let ids: Vec<String> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.owner_user_id.as_deref() == Some(owner_user_id) && r.enabled)
            .map(|r| r.id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            let tx = conn.transaction()?;
            for id in &ids {
                tx.execute(
                    "UPDATE api_keys SET enabled = 0 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
            }
            tx.commit()?;
        }
        {
            let mut runtime = write_or_recover(&self.inner.runtime);
            for rec in runtime.values_mut() {
                if rec.owner_user_id.as_deref() == Some(owner_user_id) {
                    rec.enabled = false;
                }
            }
        }
        self.bump_cred_generation();
        for id in &ids {
            self.inner.verified.invalidate_by_id(id);
        }
        Ok(ids.len())
    }

    /// 吊销动态 key：`Ok(true)` = 真的删掉了，`Ok(false)` = 本来就不存在；
    /// `Err` = **没能落库，什么都没变**（key 仍然可用）。
    ///
    /// **顺序是"先落库、后改内存"**，理由与 [`Self::create`] 对称：内存先删的话，落库失败时
    /// 会出现"内存说没了、库还在"——重启后 `load_keys` 把 key 复活（评估 §5 H2 / 记录 P1-4）；
    /// 更糟的是**重试也救不回来**：内存里已经查不到它，重试只会返回"不存在"，而库里那行还在。
    /// 先落库之后，失败时内存原样（key 仍可用），重试会重新尝试删除并最终自愈。
    pub fn delete(&self, id: &str) -> Result<bool, GatewayError> {
        // 先看它在不在：不在就是 404，且**不碰库**（与旧语义一致）。
        if !read_or_recover(&self.inner.runtime)
            .values()
            .any(|r| r.id == id)
        {
            return Ok(false);
        }
        // ① 先落库。失败 → Err，内存原样。
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute("DELETE FROM api_keys WHERE id = ?1", rusqlite::params![id])?;
        }
        // ② 再改内存 + 失效缓存 + 推进代数（并发双删时只有一个拿到 true）。
        let mut removed = false;
        {
            let mut runtime = write_or_recover(&self.inner.runtime);
            runtime.retain(|_, r| {
                if r.id == id {
                    removed = true;
                    false
                } else {
                    true
                }
            });
        }
        if removed {
            // 记录已从 runtime 表消失（查找直接 miss），这里再失效缓存并推进代数：
            // 双保险，且保证"任何凭据变更都会让旧身份失效"这条不变量成立。
            self.inner.verified.invalidate_by_id(id);
            self.bump_cred_generation();
            tracing::info!(id = %id, "api key revoked");
        }
        Ok(removed)
    }

    /// 记录一次用量并**立即同步落库**（= 内存累加 + 落库）。
    /// 吊销的 key 也有可能在途请求刚结束——按 key_id 独立累计，记录保留可审计。
    ///
    /// 仅测试使用：生产路径只做内存累加，见 [`Self::accumulate_usage`]。
    #[cfg(test)]
    pub fn record_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.record(key_id, &tenant_id, name, delta);
    }

    /// 本实例累计跑过多少次 argon2（测试断言用）。
    ///
    /// 它不单独计数：直接读 `VerifiedCache` 的计数器——也就是 `/metrics` 的
    /// `hlmg_key_verify_misses_total` 的来源，避免同一个事实在两处各记一份。
    /// 自增点见 `verified::VerifiedCache::probe_once`（"将要跑 argon2"那一处）。
    #[cfg(test)]
    pub fn argon2_runs(&self) -> usize {
        self.inner.verified.counters().1 as usize
    }

    /// 只做内存累加：纳秒级、无 IO，用于让 `/admin/usage`（读的正是这份内存计数）
    /// 在响应返回时立即一致。
    ///
    /// 实现与契约见 `usage::UsageStore::accumulate`：**这里只是转发**，不保留独立逻辑。
    pub fn accumulate_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.accumulate(key_id, &tenant_id, name, delta);
    }

    /// 是否有"内存值尚未落库"的 key（静默期返回 false，调用方可跳过整轮 flush）。
    pub fn usage_has_pending(&self) -> bool {
        self.inner.usage.has_pending()
    }

    /// 把内存里的用量**绝对累计值**批量落库（实现与契约见 `usage::UsageStore::flush_once`：
    /// 绝对值 → 幂等、重启不重复累加；成功提交后才更新"已落库"标记 → 失败下轮重试）。
    ///
    /// 返回本轮写入的 key 数；`force = true` 时忽略"是否变化"（用于关闭前落库）。
    pub fn flush_usage_once(&self, force: bool) -> usize {
        self.inner.usage.flush_once(force)
    }

    /// 关闭前落库：把全部 key 的当前值无条件写一次（可能包含未变化的，代价可忽略）。
    pub fn flush_usage_blocking(&self) -> usize {
        self.inner.usage.flush_blocking()
    }

    /// 把一次用量**增量**写穿到 SQLite（旧的每请求写库路径，**仅测试用**）。
    ///
    /// 生产路径已改为 [`Self::flush_usage_once`]：按周期把各 key 的绝对累计值批量写一次。
    /// 增量写每次都要抢全局 `db` 锁并提交事务，实测把 2 vCPU 的吞吐摁在约 190 QPS，
    /// 所以只留给测试构造"库里已有某值"的场景。**阻塞调用**，不要放回请求路径。
    #[cfg(test)]
    pub fn persist_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.persist(key_id, &tenant_id, name, delta);
    }

    /// 单个 key 的用量快照（无记录 → None）。
    pub fn usage_of(&self, key_id: &str) -> Option<KeyUsageInfo> {
        self.inner.usage.of(key_id)
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub fn usage_snapshot(&self) -> Vec<KeyUsageInfo> {
        self.inner.usage.snapshot()
    }
}

#[cfg(test)]
mod tests;
