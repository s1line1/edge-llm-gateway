//! Tenant aggregate methods.

use super::*;
use crate::storage::hash::{constant_time_eq, lookup_of, now_secs};
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

fn validate_tenant_name(name: &str) -> Result<String, TenantError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(TenantError::InvalidName);
    }
    Ok(name.to_string())
}

impl Storage {
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
}
