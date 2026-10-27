//! session token 哈希存储、授权、撤销与持久化测试。

use super::*;

fn cheap() -> crate::storage::hash::CheapArgon2 {
    crate::storage::hash::CheapArgon2::install()
}

fn user(store: &Storage) -> String {
    store
        .create_user(
            "alice".into(),
            "correct horse battery".into(),
            UserRole::SuperAdmin,
            None,
            None,
        )
        .unwrap()
        .record
        .id()
        .to_string()
}

#[test]
fn session_authorization_and_revocation() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let user_id = user(&store);
    let created = store.create_session(&user_id, 60).unwrap();
    assert_eq!(created.token.len(), 64);
    assert_eq!(created.csrf_token.len(), 64);
    assert_eq!(store.session_count(), 1);
    assert_eq!(
        store.authorize_session(&created.token).unwrap().id(),
        user_id
    );
    assert!(store.revoke_session(&created.token));
    assert!(store.authorize_session(&created.token).is_none());
    assert_eq!(store.session_count(), 0);
}

#[test]
fn disabling_a_user_revokes_all_sessions() {
    let _cheap = cheap();
    let store = Storage::new(None);
    let user_id = user(&store);
    store
        .create_user(
            "root2".into(),
            "correct horse battery".into(),
            UserRole::SuperAdmin,
            None,
            None,
        )
        .unwrap();
    let a = store.create_session(&user_id, 60).unwrap();
    let b = store.create_session(&user_id, 60).unwrap();
    store
        .update_user(
            &user_id,
            UserPatch {
                enabled: Some(false),
                ..UserPatch::default()
            },
        )
        .unwrap();
    assert!(store.authorize_session(&a.token).is_none());
    assert!(store.authorize_session(&b.token).is_none());
    assert_eq!(store.session_count(), 0);
}

#[test]
fn sessions_survive_reopen_and_expired_rows_are_pruned() {
    let _cheap = cheap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let user_id = user(&store);
    let created = store.create_session(&user_id, 60).unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(&created.token));
    assert!(!text.contains(&created.csrf_token));
    let reopened = Storage::new(Some(path));
    assert_eq!(
        reopened.authorize_session(&created.token).unwrap().id(),
        user_id
    );
    assert_eq!(reopened.prune_expired_sessions(u64::MAX), 1);
    assert!(reopened.authorize_session(&created.token).is_none());
}
