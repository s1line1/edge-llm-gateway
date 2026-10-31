//! Dashboard session aggregate methods.

use super::*;
use crate::storage::hash::now_secs;
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

impl Storage {
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
}
