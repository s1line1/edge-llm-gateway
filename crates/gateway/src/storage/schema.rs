//! 库结构本身：DDL、侧车权限、加列探测与旧库迁移。
//!
//! 从 `storage/mod.rs` 切出来的理由：这些定义的变更理由是**库的版本**——加一张表、
//! 加一列、改一次迁移；而 `Storage` 的变更理由是**凭据与用量的语义**。两者混在一个
//! 1500 行的文件里时，"改 schema"与"改鉴权"在 diff 上长得一模一样。
//!
//! 读写路径全部由 `storage/mod.rs`（凭据）与 `storage/usage.rs`（账本）持有；
//! 本模块只提供表定义与装载/迁移函数，不持有任何状态。

use std::collections::HashMap;

use rusqlite::Connection;

use super::hash::{hash_argon2, lookup_of};
use super::tenant::{default_tenant, TenantRecord, DEFAULT_TENANT_ID, DEFAULT_TENANT_NAME};
use super::KeyRecord;

pub(super) const TENANT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    max_concurrent_requests INTEGER NOT NULL DEFAULT 0,
    requests_per_minute INTEGER NOT NULL DEFAULT 0,
    agent_token_hash TEXT NOT NULL DEFAULT ''
)";

pub(super) const API_KEY_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    lookup TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    cred_version INTEGER NOT NULL DEFAULT 1,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    owner_user_id TEXT NULL
)";

/// Dashboard 用户。`tenant_id` 只在 super_admin 上为 NULL；角色/租户一致性由
/// `Storage` 的应用层校验（旧库没有 CHECK 成本更低的迁移路径）。
pub(super) const USER_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('super_admin','tenant_admin','user')),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NULL
)";

/// 用户名大小写不敏感唯一：登录不要求 tenant slug，因此全局唯一。
pub(super) const USERNAME_INDEX: &str =
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)";

/// 服务端会话。只存 `sha256(session_token)`，不存明文 token。
pub(super) const SESSION_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
)";

pub(super) const SESSION_USER_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)";

/// 特权写操作审计。刻意不存密码/session/API key/agent token。
pub(super) const ADMIN_AUDIT_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS admin_audit (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT NULL,
    actor_label TEXT NOT NULL,
    tenant_id TEXT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
)";

pub(super) const USAGE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS key_usage (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0,
    estimated_requests INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    tenant_id TEXT NOT NULL DEFAULT 'default'
)";

/// 表已存在时补一列；列已存在则跳过。`definition` 是代码常量，不拼接用户输入。
pub(super) fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    if !table_has_column(conn, table, column)? {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))?;
    }
    Ok(())
}

/// 确保内置 default tenant 存在；旧库迁移和全新库都走这里。
pub(super) fn ensure_default_tenant(conn: &Connection) -> rusqlite::Result<()> {
    let tenant = default_tenant();
    conn.execute(
        "INSERT OR IGNORE INTO tenants
         (id, name, created_at, enabled, max_concurrent_requests, requests_per_minute, agent_token_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            DEFAULT_TENANT_ID,
            DEFAULT_TENANT_NAME,
            tenant.created_at() as i64,
            i64::from(tenant.enabled()),
            tenant.max_concurrent_requests() as i64,
            tenant.requests_per_minute() as i64,
            tenant.agent_token_hash(),
        ],
    )?;
    Ok(())
}

/// 从 SQLite 加载全部租户。
pub(super) fn load_tenants(conn: &Connection) -> rusqlite::Result<HashMap<String, TenantRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, enabled, max_concurrent_requests, requests_per_minute, agent_token_hash
         FROM tenants",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TenantRecord::new(
            r.get(0)?,
            r.get(1)?,
            r.get::<_, i64>(2)? as u64,
            r.get::<_, i64>(3)? != 0,
            r.get::<_, i64>(4)? as u32,
            r.get::<_, i64>(5)? as u32,
            r.get(6)?,
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.id().to_string(), rec);
    }
    Ok(map)
}

/// 迁移旧版库（明文 key 表，无 lookup/key_hash 列）为 argon2 哈希存储。
/// 旧库存的是明文，可无损重哈希；迁移后删除明文表。已是新 schema 时直接跳过。
/// 返回迁移的 key 条数。
///
/// 注意：同步执行 + 全量读入 + 单一大事务，**仅适合小数据量**（个人/小团队、不介意
/// 极端情况下重发 key）；大规模升级请走离线迁移（见 DEPLOY.md §10 与 TODO.md P1）。
pub(super) fn migrate_legacy_keys(conn: &mut Connection) -> rusqlite::Result<usize> {
    if table_has_column(conn, "api_keys", "lookup")? {
        return Ok(0); // 已是新 schema
    }

    // 读取旧行（明文 key → 重哈希）；旧表可能为空，也要重建结构
    let mut rows = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT id, key, name, created_at, enabled FROM api_keys")?;
        let iter = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        for row in iter {
            let (id, plaintext, name, created_at, enabled) = row?;
            rows.push((
                id,
                lookup_of(&plaintext),
                hash_argon2(&plaintext),
                name,
                created_at,
                enabled,
            ));
        }
    }

    let tx = conn.transaction()?;
    tx.execute("ALTER TABLE api_keys RENAME TO api_keys_legacy", [])?;
    tx.execute_batch(API_KEY_SCHEMA)?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (id, lookup, key_hash, name, created_at, enabled) in &rows {
            ins.execute(rusqlite::params![
                id, lookup, key_hash, name, created_at, enabled
            ])?;
        }
    }
    tx.execute("DROP TABLE api_keys_legacy", [])?;
    tx.commit()?;
    // 回收 freelist：DROP 后旧明文页可能仍残留在文件中，VACUUM 重写数据库以清除
    if let Err(e) = conn.execute_batch("VACUUM") {
        tracing::warn!("keys db vacuum after migration failed: {e}");
    }
    Ok(rows.len())
}

/// 检查表是否包含指定列（表名来自代码常量，不拼接用户输入）。
pub(super) fn table_has_column(
    conn: &Connection,
    table: &str,
    column: &str,
) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for c in cols {
        if c? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 从 SQLite 加载全部 dashboard 用户（key = user id）。
pub(super) fn load_users(
    conn: &Connection,
) -> rusqlite::Result<HashMap<String, super::user::UserRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, tenant_id, username, password_hash, role, enabled, created_at, updated_at, last_login_at, created_by
         FROM users",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(super::user::UserRecord::from_parts(
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get::<_, String>(4)?
                .parse::<super::user::UserRole>()
                .unwrap_or(super::user::UserRole::User),
            r.get::<_, i64>(5)? != 0,
            r.get::<_, i64>(6)? as u64,
            r.get::<_, i64>(7)? as u64,
            r.get::<_, i64>(8)? as u64,
            r.get(9)?,
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.id().to_string(), rec);
    }
    Ok(map)
}

/// 从 SQLite 加载全部会话（key = token_hash）。
pub(super) fn load_sessions(
    conn: &Connection,
) -> rusqlite::Result<HashMap<String, super::session::SessionRecord>> {
    let mut stmt =
        conn.prepare("SELECT id, user_id, token_hash, created_at, expires_at FROM sessions")?;
    let rows = stmt.query_map([], |r| {
        Ok(super::session::SessionRecord::from_parts(
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get::<_, i64>(3)? as u64,
            r.get::<_, i64>(4)? as u64,
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.token_hash().to_string(), rec);
    }
    Ok(map)
}

/// 从 SQLite 加载全部动态 key（key = lookup）。
pub(super) fn load_keys(conn: &Connection) -> rusqlite::Result<HashMap<String, KeyRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, lookup, key_hash, name, created_at, enabled, cred_version, tenant_id, owner_user_id
         FROM api_keys",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(KeyRecord {
            id: r.get(0)?,
            lookup: r.get(1)?,
            key_hash: r.get(2)?,
            name: r.get(3)?,
            created_at: r.get::<_, i64>(4)? as u64,
            enabled: r.get::<_, i64>(5)? != 0,
            // 迁移前的老行是 NULL → 0；0 不是合法代数（代数从 1 起），归一到 1
            cred_version: r.get::<_, Option<i64>>(6)?.unwrap_or(1).max(1) as u64,
            tenant_id: r.get(7)?,
            owner_user_id: r.get(8)?,
        })
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let rec = row?;
        map.insert(rec.lookup.clone(), rec);
    }
    Ok(map)
}
