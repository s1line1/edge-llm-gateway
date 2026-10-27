//! storage 测试：tenant 模型、迁移与 key/usage 归属。

use super::*;
use crate::storage::hash::{hash_argon2, lookup_of};
use crate::storage::tenant::DEFAULT_TENANT_ID;

/// 前置 schema（无 tenants、api_keys/key_usage 无 tenant_id），模拟升级前的库。
const OLD_API_KEYS: &str = "CREATE TABLE api_keys (
    id TEXT PRIMARY KEY, lookup TEXT NOT NULL UNIQUE, key_hash TEXT NOT NULL,
    name TEXT NOT NULL, created_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    cred_version INTEGER NOT NULL DEFAULT 1
)";
const OLD_USAGE: &str = "CREATE TABLE key_usage (
    key_id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
    prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
    requests INTEGER NOT NULL DEFAULT 0, estimated_requests INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER NOT NULL DEFAULT 0
)";

#[test]
fn pre_tenant_database_migrates_to_default_tenant() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let token = "sk-legacy-tenant-test";
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(OLD_API_KEYS).unwrap();
        conn.execute_batch(OLD_USAGE).unwrap();
        conn.execute(
            "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled, cred_version)
             VALUES ('deadbeef', ?1, ?2, 'legacy', 1, 1, 1)",
            rusqlite::params![lookup_of(token), hash_argon2(token)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO key_usage (key_id, name, prompt_tokens, completion_tokens, requests, last_used_at)
             VALUES ('deadbeef', 'legacy', 7, 5, 2, 1)",
            [],
        )
        .unwrap();
    }

    let store = Storage::new(Some(path.clone()));
    assert!(store.persistence_state().is_none_or(|r| r.is_ok()));
    assert_eq!(store.tenant(DEFAULT_TENANT_ID).unwrap().name(), "default");
    assert!(store.authorize(token), "legacy key must still authorize");
    let usage = store
        .usage_of("deadbeef")
        .expect("usage row survives migration");
    assert_eq!(usage.tenant_id, DEFAULT_TENANT_ID);
    assert_eq!(usage.total_tokens, 12);
    let key = store
        .list()
        .into_iter()
        .find(|k| k.id() == "deadbeef")
        .expect("legacy key survives migration");
    assert_eq!(key.tenant_id(), DEFAULT_TENANT_ID);
}

#[test]
fn tenant_crud_and_key_usage_filtering() {
    let dir = tempdir().unwrap();
    let store = Storage::new(Some(dir.path().join("keys.db")));

    let created = store.create_tenant("alpha".into(), 1, 60).unwrap();
    let alpha = created.record.id().to_string();
    assert_eq!(created.agent_token.len(), 64);
    assert!(store.tenant(&alpha).is_some());
    assert_eq!(
        store.create_tenant("alpha".into(), 0, 0).unwrap_err(),
        TenantError::NameTaken
    );

    let key = store.create_in(&alpha, None, "alpha-key".into()).unwrap();
    assert_eq!(key.record.tenant_id(), alpha);
    assert_eq!(store.key_count_for_tenant(&alpha), 1);
    assert_eq!(store.list_for_tenant(&alpha).len(), 1);
    assert!(store.list_for_tenant(DEFAULT_TENANT_ID).is_empty());

    store.accumulate_usage(
        key.record.id(),
        "alpha-key",
        &UsageDelta {
            prompt_tokens: 3,
            completion_tokens: 4,
            estimated: false,
        },
    );
    let info = store.usage_for_tenant(&alpha);
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].tenant_id, alpha);
    assert_eq!(store.tenant_totals(&alpha), (3, 4, 7, 1));

    let updated = store
        .update_tenant(
            &alpha,
            TenantPatch {
                requests_per_minute: Some(10),
                ..TenantPatch::default()
            },
        )
        .unwrap();
    assert_eq!(updated.requests_per_minute(), 10);
    assert_eq!(
        store.delete_tenant(&alpha).unwrap_err(),
        TenantError::HasKeys
    );
    assert_eq!(
        store.delete_tenant(DEFAULT_TENANT_ID).unwrap_err(),
        TenantError::DefaultTenant
    );

    store.delete(key.record.id()).unwrap();
    store.delete_tenant(&alpha).unwrap();
    assert!(store.tenant(&alpha).is_none());
}

#[test]
fn default_tenant_cannot_be_disabled_or_renamed() {
    let store = Storage::new(None);
    assert_eq!(
        store
            .update_tenant(
                DEFAULT_TENANT_ID,
                TenantPatch {
                    enabled: Some(false),
                    ..TenantPatch::default()
                },
            )
            .unwrap_err(),
        TenantError::DefaultTenant
    );
    assert_eq!(
        store
            .update_tenant(
                DEFAULT_TENANT_ID,
                TenantPatch {
                    name: Some("renamed".into()),
                    ..TenantPatch::default()
                },
            )
            .unwrap_err(),
        TenantError::DefaultTenant
    );
}

#[test]
fn agent_token_verification_and_rotation() {
    let store = Storage::new(None);
    let created = store.create_tenant("agents".into(), 0, 0).unwrap();
    let id = created.record.id().to_string();
    assert_eq!(
        store
            .verify_agent_token(&id, &created.agent_token)
            .unwrap()
            .id(),
        id
    );
    assert_eq!(
        store.verify_agent_token(&id, "not-a-token").unwrap_err(),
        TenantError::BadToken
    );
    assert_eq!(
        store
            .verify_agent_token(DEFAULT_TENANT_ID, "anything")
            .unwrap_err(),
        TenantError::BadToken,
        "default tenant has no agent token; legacy Register is the only entry"
    );

    let new_token = store.rotate_agent_token(&id).unwrap();
    assert_eq!(
        store
            .verify_agent_token(&id, &created.agent_token)
            .unwrap_err(),
        TenantError::BadToken,
        "rotation must invalidate the old token"
    );
    assert!(store.verify_agent_token(&id, &new_token).is_ok());

    store
        .update_tenant(
            &id,
            TenantPatch {
                enabled: Some(false),
                ..TenantPatch::default()
            },
        )
        .unwrap();
    assert_eq!(
        store.verify_agent_token(&id, &new_token).unwrap_err(),
        TenantError::Disabled
    );
}
