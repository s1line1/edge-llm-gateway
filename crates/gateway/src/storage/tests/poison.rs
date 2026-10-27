//! storage 测试：锁中毒后的可用性。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享导入。

use super::*;
/// 规格（评估 §5 H4 / §7 步骤 6）：**守卫内 panic 之后，认证热路径不能永久 500**。
///
/// `runtime` 是热路径第一站，也是全局共享的：它一旦中毒，`.read().unwrap()` 会让
/// 之后**每个** `/v1/*` 都 panic（进程活着、指标还在跑，但全站 500）。锁里的数据只是
/// 内存映射，守卫内 panic 不会让它变成非法状态，所以继续用是安全的。
#[test]
#[serial]
fn a_poisoned_runtime_lock_does_not_take_the_gateway_down() {
    let store = Storage::new(None);
    let key = store.create("poison-runtime".into()).unwrap();
    assert!(store.authorize(&key.plaintext), "前提：这把 key 可用");

    // 持写锁时 panic：锁中毒，但表本身仍然合法
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = store.inner.runtime.write().unwrap();
        panic!("poison the runtime lock");
    }));
    assert!(poisoned.is_err(), "前提：panic 确实发生了");
    assert!(
        store.inner.runtime.is_poisoned(),
        "前提：锁确实中毒了（否则这条测试没测到东西）"
    );

    // 中毒之后：读（授权/列表）与写（建 key）都必须照常工作
    assert!(store.authorize(&key.plaintext), "锁中毒不应让所有请求 500");
    assert!(store.create("after-poison".into()).is_ok());
    assert_eq!(store.list().len(), 2);
}

/// 同 [`a_poisoned_runtime_lock_does_not_take_the_gateway_down`]，但针对**落库连接**
/// 那把锁（`db`）：它同时服务凭据写穿与用量落库，中毒后不该让"建 key"直接 500。
#[test]
#[serial]
fn a_poisoned_db_lock_still_lets_credential_writes_through() {
    let dir = tempfile::tempdir().unwrap();
    let store = Storage::new(Some(dir.path().join("keys.db")));

    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = store.inner.db.lock().unwrap();
        panic!("poison the db lock");
    }));
    assert!(poisoned.is_err(), "前提：panic 确实发生了");
    assert!(store.inner.db.is_poisoned(), "前提：锁确实中毒了");

    let created = store
        .create("after-poison-db".into())
        .expect("锁中毒后仍应能落库");
    assert!(store.authorize(&created.plaintext));
    // 库里确实有一行（不是只改了内存）
    let conn = Connection::open(dir.path().join("keys.db")).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1, "锁中毒不该把落库也堵死");
}
