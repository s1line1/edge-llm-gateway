//! dashboard 用户/角色/租户一致性与 API key ownership 的存储测试。

use super::*;

fn cheap() -> crate::storage::hash::CheapArgon2 {
    crate::storage::hash::CheapArgon2::install()
}

fn tenant(store: &Storage, name: &str) -> String {
    store
        .create_tenant(name.into(), 0, 0)
        .unwrap()
        .record
        .id()
        .to_string()
}

#[test]
fn user_crud_normalizes_username_and_never_exposes_hash() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let tenant_id = tenant(&store, "alpha");
    let created = store
        .create_user(
            "  Alice.01 ".into(),
            "correct horse battery".into(),
            UserRole::TenantAdmin,
            Some(tenant_id.clone()),
            None,
        )
        .unwrap();
    assert_eq!(created.record.username(), "alice.01");
    assert_eq!(created.record.tenant_id(), Some(tenant_id.as_str()));
    assert_eq!(store.user_count(), 1);
    assert_eq!(store.user_count_for_tenant(&tenant_id), 1);
    assert!(store
        .create_user(
            "ALICE.01".into(),
            "another long password".into(),
            UserRole::User,
            Some(tenant_id.clone()),
            None,
        )
        .is_err());
    let debug = format!("{:?}", created.record);
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("$argon2id$"));

    let updated = store
        .update_user(
            created.record.id(),
            UserPatch {
                enabled: Some(false),
                ..UserPatch::default()
            },
        )
        .unwrap();
    assert!(!updated.enabled());
    assert!(
        store.user_by_username("ALICE.01").is_none()
            || !store.user_by_username("alice.01").unwrap().enabled()
    );
    store.delete_user(created.record.id()).unwrap();
    assert_eq!(store.user_count(), 0);
}

#[test]
fn role_tenant_consistency_is_enforced() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let tenant_id = tenant(&store, "alpha");
    assert!(store
        .create_user(
            "root".into(),
            "correct horse battery".into(),
            UserRole::SuperAdmin,
            Some(tenant_id.clone()),
            None,
        )
        .is_err());
    assert!(store
        .create_user(
            "tenantless".into(),
            "correct horse battery".into(),
            UserRole::TenantAdmin,
            None,
            None,
        )
        .is_err());
    assert!(store
        .create_user(
            "bad-role".into(),
            "correct horse battery".into(),
            UserRole::User,
            Some("missing".into()),
            None,
        )
        .is_err());
}

#[test]
fn last_super_admin_cannot_be_removed() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let root = store
        .create_user(
            "root".into(),
            "correct horse battery".into(),
            UserRole::SuperAdmin,
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        store
            .update_user(
                root.record.id(),
                UserPatch {
                    enabled: Some(false),
                    ..UserPatch::default()
                },
            )
            .unwrap_err(),
        UserError::LastSuperAdmin
    );
    assert_eq!(
        store.delete_user(root.record.id()).unwrap_err(),
        UserError::LastSuperAdmin
    );
}

#[test]
fn api_key_owner_filtering_and_disable() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let tenant_id = tenant(&store, "alpha");
    let user = store
        .create_user(
            "alice".into(),
            "correct horse battery".into(),
            UserRole::User,
            Some(tenant_id.clone()),
            None,
        )
        .unwrap();
    let owned = store
        .create_in(&tenant_id, Some(user.record.id()), "mine".into())
        .unwrap();
    let tenant_level = store.create_in(&tenant_id, None, "shared".into()).unwrap();
    assert_eq!(store.list_for_owner(&tenant_id, user.record.id()).len(), 1);
    assert_eq!(store.list_for_tenant(&tenant_id).len(), 2);
    assert!(store.authorize(&owned.plaintext));
    assert_eq!(store.disable_keys_for_owner(user.record.id()).unwrap(), 1);
    assert!(!store.authorize(&owned.plaintext));
    assert!(store.authorize(&tenant_level.plaintext));
    assert_eq!(owned.record.owner_user_id(), Some(user.record.id()));
}

#[test]
fn audit_rows_are_bounded_and_have_no_secret_fields() {
    let _cheap = cheap();
    let dir = tempdir().unwrap();
    let store = Storage::new(Some(dir.path().join("keys.db")));
    store
        .append_audit(Some("u1"), "alice", Some("t1"), "user.create", "target")
        .unwrap();
    let rows = store.audit_records(None, 100);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action(), "user.create");
}

#[test]
fn opening_a_pre_user_database_is_additive() {
    let _cheap = cheap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                lookup TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                cred_version INTEGER NOT NULL DEFAULT 1,
                tenant_id TEXT NOT NULL DEFAULT 'default'
             );
             INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled, cred_version, tenant_id)
             VALUES ('old-key', 'old-lookup', 'old-hash', 'legacy', 1, 1, 1, 'default');",
        )
        .unwrap();
    }
    let store = Storage::new(Some(path.clone()));
    assert_eq!(store.user_count(), 0);
    assert_eq!(store.session_count(), 0);
    let keys = store.list();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].owner_user_id(), None);
    let conn = rusqlite::Connection::open(path).unwrap();
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(api_keys)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .flatten()
        .collect();
    assert!(columns.iter().any(|c| c == "owner_user_id"));
}
