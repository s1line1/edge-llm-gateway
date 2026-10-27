//! storage 测试：凭据 CRUD、持久化往返与“失败不改进内存态”的契约。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享导入。

use super::*;
#[test]
fn persist_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("dsh".into()).unwrap();
    assert!(
        store.authorize(&created.plaintext),
        "new key should authorize"
    );
    assert!(!store.authorize("nope"));
    drop(store);

    let reloaded = Storage::new(Some(path.clone()));
    assert!(
        reloaded.authorize(&created.plaintext),
        "persisted key should survive reload"
    );
}

#[test]
fn plaintext_never_persisted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("sec".into()).unwrap();
    drop(store); // 确保落盘

    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains(&created.plaintext),
        "plaintext key must not be persisted"
    );
    assert!(
        text.contains("$argon2id$"),
        "argon2 hash should be persisted"
    );
    // 明文不落盘后，重启依然能通过哈希校验授权
    let reloaded = Storage::new(Some(path.clone()));
    assert!(reloaded.authorize(&created.plaintext));
    assert!(!reloaded.authorize("wrong"));
}

#[test]
fn delete_revokes_and_persists() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("x".into()).unwrap();
    assert!(store.authorize(&created.plaintext));
    assert!(store.delete(&created.record.id).unwrap());
    assert!(
        !store.authorize(&created.plaintext),
        "revoked key must be rejected"
    );
    assert!(
        !store.delete(&created.record.id).unwrap(),
        "deleting twice returns false"
    );

    // 吊销同样持久化：重载后 key 依然失效
    let reloaded = Storage::new(Some(path.clone()));
    assert!(
        !reloaded.authorize(&created.plaintext),
        "revocation should survive reload"
    );
}

#[test]
fn authorize_rejects_unknown_lookup_without_argon2() {
    // lookup 不在表中直接拒绝，不做无意义的 argon2 计算
    let store = Storage::new(None);
    assert!(!store.authorize("sk-not-a-real-key"));
}

/// 规格：**持久化失败时不能声称"创建成功"**（评估报告 §5 H2 / 记录 P2-9）。
///
/// 触发方式：给 `api_keys` 加一个必然 ABORT 的 INSERT 触发器——磁盘满 / I/O 错误 /
/// `SQLITE_BUSY` 在真实世界里就是这一支。修改前 `create` 先写内存、后落库，落库失败只
/// `warn!` 然后照常返回 → 管理页显示一把**重启后就消失**的 key。
#[test]
fn create_that_fails_to_persist_leaves_no_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER dbg_reject_insert BEFORE INSERT ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: persist refused'); END;",
        )
        .unwrap();
    }

    assert!(
        store.create("cannot-persist".into()).is_err(),
        "落库失败必须让调用方知道（admin 要回 500，而不是 201 + 一把假 key）"
    );
    assert!(
        store.list().is_empty(),
        "落库失败就不该留下任何条目——重启后它会消失，等于发了一把假 key"
    );
    let conn = Connection::open(&path).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "库里当然也没有");
}

/// 规格：**吊销落库失败时 key 必须仍然可用**（评估报告 §5 H2 / 记录 P1-4）。
///
/// 与上一条对称：修改前 `delete` 先删内存、后落库，落库失败只 `warn!` 却仍返回 `true`
/// → admin 回 204、日志写 "api key revoked"，而重启后 `load_keys` 会把 key 复活。
/// 正确语义只有两种：内存与库**一起变**，或**都不变**——绝不能"内存说没了、库还在"。
#[test]
fn delete_that_fails_to_persist_keeps_the_key_usable() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("cannot-delete".into()).unwrap();
    assert!(store.authorize(&created.plaintext), "前提：这把 key 可用");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER dbg_reject_delete BEFORE DELETE ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: persist refused'); END;",
        )
        .unwrap();
    }

    assert!(
        store.delete(&created.record.id).is_err(),
        "吊销没能落库必须让调用方知道（admin 要回 500）"
    );
    assert!(
        store.authorize(&created.plaintext),
        "吊销没能落库时 key 必须仍然可用——否则操作员看到 204、重启后它又活了"
    );
    let conn = Connection::open(&path).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1, "库里那一行也还在");
}

#[test]
fn verify_rejects_malformed_hash() {
    // 存储的哈希不是合法 PHC 格式 → 校验直接拒绝（不 panic）
    assert!(!verify_argon2("sk-anything", "not-a-phc-hash"));
    assert!(!verify_argon2("sk-anything", ""));
}

/// 规格（S2-4）：id 冲突必须报错并保留第一行，不能 `INSERT OR REPLACE` 静默替换。
#[test]
fn duplicate_id_insert_is_rejected_not_replaced() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path));
    let first = KeyRecord {
        id: "0123456789abcdef0123456789abcdef".into(),
        lookup: "lookup-first".into(),
        key_hash: "hash-first".into(),
        name: "first".into(),
        created_at: 1,
        enabled: true,
        cred_version: 1,
    };
    let mut second = first.clone();
    second.lookup = "lookup-second".into();
    second.key_hash = "hash-second".into();
    second.name = "second".into();

    let mut guard = store.inner.db.lock().unwrap();
    let conn = guard.as_mut().unwrap();
    insert_api_key(conn, &first).unwrap();
    let err = insert_api_key(conn, &second).expect_err("duplicate id must fail");
    assert!(
        matches!(
            err,
            rusqlite::Error::SqliteFailure(ref e, _)
                if e.code == rusqlite::ErrorCode::ConstraintViolation
        ),
        "expected a constraint violation, got {err:?}"
    );
    let name: String = conn
        .query_row(
            "SELECT name FROM api_keys WHERE id = ?1",
            [&first.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(name, "first", "the original row must not be replaced");
}

/// 规格（CON-002）：历史库里的 8 字符 id 仍能通过 `Storage::new` 载入。
#[test]
fn eight_character_legacy_id_still_loads() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    {
        let mut guard = store.inner.db.lock().unwrap();
        let conn = guard.as_mut().unwrap();
        conn.execute(
            "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
             VALUES ('deadbeef', 'legacy-lookup', 'legacy-hash', 'legacy', 1, 1)",
            [],
        )
        .unwrap();
    }
    drop(store);

    let reloaded = Storage::new(Some(path));
    assert!(
        reloaded.list().iter().any(|r| r.id == "deadbeef"),
        "8-character legacy id must still load"
    );
    assert!(reloaded.usage_of("deadbeef").is_none());
}
