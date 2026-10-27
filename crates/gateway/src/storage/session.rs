//! 服务端 session 数据形状与 token 生成。
//!
//! 数据库只保存 `sha256(token)`；明文 token 只存在于登录响应的 `Set-Cookie` 和客户端
//! cookie 中。CSRF token 与 session token 独立生成，用于 cookie 双提交。

use crate::storage::hash::{hex_lower, lookup_of};

/// 一条 session。`token_hash = sha256(token)`；明文 token 不进入本结构。
#[derive(Clone)]
pub struct SessionRecord {
    id: String,
    user_id: String,
    token_hash: String,
    created_at: u64,
    expires_at: u64,
}

impl SessionRecord {
    pub(crate) fn from_parts(
        id: String,
        user_id: String,
        token_hash: String,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            id,
            user_id,
            token_hash,
            created_at,
            expires_at,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl std::fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("token_hash", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// 登录成功返回的一次性 session 材料。`token` 只进 HttpOnly cookie，`csrf_token` 进
/// 非 HttpOnly cookie；调用方不得把 `token` 放进 JSON。
pub struct CreatedSession {
    pub record: SessionRecord,
    pub token: String,
    pub csrf_token: String,
}

pub(crate) fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("os rng");
    hex_lower(&bytes)
}

pub(crate) fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("os rng");
    hex_lower(&bytes)
}

pub(crate) fn session_token_hash(token: &str) -> String {
    lookup_of(token)
}

pub(crate) fn generate_session_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("os rng");
    hex_lower(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_not_plaintext_and_is_stable() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        assert_eq!(session_token_hash(&token), session_token_hash(&token));
        assert!(!session_token_hash(&token).contains(&token));
        assert_ne!(generate_session_token(), generate_session_token());
        assert_eq!(generate_csrf_token().len(), 64);
    }

    #[test]
    fn session_debug_redacts_hash() {
        let record =
            SessionRecord::from_parts("s1".into(), "u1".into(), "secret-hash".into(), 1, 2);
        let rendered = format!("{record:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("secret-hash"));
    }
}
