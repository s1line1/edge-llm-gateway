//! Dashboard user aggregate methods.

use super::*;
use crate::storage::hash::{hash_argon2, now_secs};
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

impl Storage {
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
}
