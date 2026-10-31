//! Admin audit aggregate methods.

use super::*;
use crate::storage::hash::now_secs;
use crate::sync::lock_or_recover;

impl Storage {
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
}
