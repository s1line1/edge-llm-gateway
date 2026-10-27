//! storage 测试：用量累加、批量落库与关闭前 flush。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享导入。

use super::*;
#[test]
fn usage_accumulates_and_persists() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("usage-test".into()).unwrap();
    let id = created.record.id.clone();

    // 3 次请求：2 次精确 usage + 1 次估算
    store.record_usage(
        &id,
        "usage-test",
        &UsageDelta {
            prompt_tokens: 10,
            completion_tokens: 20,
            estimated: false,
        },
    );
    store.record_usage(
        &id,
        "usage-test",
        &UsageDelta {
            prompt_tokens: 5,
            completion_tokens: 5,
            estimated: false,
        },
    );
    store.record_usage(
        &id,
        "usage-test",
        &UsageDelta {
            prompt_tokens: 100,
            completion_tokens: 50,
            estimated: true,
        },
    );
    let info = store.usage_of(&id).unwrap();
    assert_eq!(info.prompt_tokens, 115);
    assert_eq!(info.completion_tokens, 75);
    assert_eq!(info.total_tokens, 190);
    assert_eq!(info.requests, 3);
    assert_eq!(info.estimated_requests, 1);
    assert_eq!(info.name, "usage-test");
    assert!(info.last_used_at > 0);

    // 持久化：重载后用量仍在（吊销 key 也不丢记录，可审计）
    drop(store);
    let reloaded = Storage::new(Some(path.clone()));
    let again = reloaded.usage_of(&id).unwrap();
    assert_eq!(again.prompt_tokens, 115);
    assert_eq!(again.completion_tokens, 75);
    assert_eq!(again.requests, 3);
    assert_eq!(again.estimated_requests, 1);

    // 吊销 key 后 usage 记录仍保留（key 删了，用量表独立）
    let store2 = Storage::new(Some(path.clone()));
    store2.delete(&id).unwrap();
    drop(store2);
    let store3 = Storage::new(Some(path));
    let kept = store3.usage_of(&id).unwrap();
    assert_eq!(kept.requests, 3, "usage survives key revocation");
}

#[test]
fn usage_accumulates_in_memory_and_flushes_in_one_batch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let a = store.create("batch-a".into()).unwrap();
    let b = store.create("batch-b".into()).unwrap();
    let delta = UsageDelta {
        prompt_tokens: 10,
        completion_tokens: 20,
        estimated: false,
    };

    for _ in 0..100 {
        store.accumulate_usage(&a.record.id, "batch-a", &delta);
    }
    for _ in 0..50 {
        store.accumulate_usage(&b.record.id, "batch-b", &delta);
    }

    // ① 累加本身不碰库：/admin/usage 读内存，立即一致（这是原有语义，不能退步）
    assert_eq!(store.usage_of(&a.record.id).unwrap().requests, 100);
    assert_eq!(store.usage_of(&b.record.id).unwrap().requests, 50);
    assert!(store.usage_has_pending(), "累加后应报告有待落库数据");
    let fresh = Storage::new(Some(path.clone()));
    assert!(
        fresh.usage_of(&a.record.id).is_none(),
        "未 flush 前不应有库记录"
    );

    // ② 一个周期把两个 key 各写一行
    assert_eq!(store.flush_usage_once(false), 2);
    assert!(!store.usage_has_pending(), "flush 后不应再有待落库数据");

    // ③ 幂等：没有新用量时再 flush 是空操作（不会重复累加）
    assert_eq!(store.flush_usage_once(false), 0);
    assert_eq!(
        store.flush_usage_once(true),
        2,
        "force 会无条件重写，值仍应是绝对值"
    );

    // ④ 重启（新建 store 读同一个库）后用量仍在，且不重复累加
    let reloaded = Storage::new(Some(path.clone()));
    let info = reloaded.usage_of(&a.record.id).unwrap();
    assert_eq!(info.requests, 100);
    assert_eq!(info.prompt_tokens, 1000);
    assert_eq!(info.completion_tokens, 2000);
    assert_eq!(reloaded.usage_of(&b.record.id).unwrap().requests, 50);
}

#[test]
fn shutdown_flush_writes_without_waiting_for_the_period() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("shutdown".into()).unwrap();
    store.accumulate_usage(
        &created.record.id,
        "shutdown",
        &UsageDelta {
            prompt_tokens: 7,
            completion_tokens: 8,
            estimated: false,
        },
    );

    // 关闭前的强制落库：不等 flush 周期，立刻可见
    let store2 = store.clone();
    assert_eq!(store2.flush_usage_blocking(), 1);

    let fresh = Storage::new(Some(path));
    let info = fresh.usage_of(&created.record.id).unwrap();
    assert_eq!(info.requests, 1);
    assert_eq!(info.total_tokens, 15);
}

#[test]
fn usage_in_memory_only_store() {
    let store = Storage::new(None);
    store.record_usage(
        "mem-key",
        "m",
        &UsageDelta {
            prompt_tokens: 1,
            completion_tokens: 2,
            estimated: false,
        },
    );
    let info = store.usage_of("mem-key").unwrap();
    assert_eq!(info.total_tokens, 3);
    assert_eq!(store.usage_snapshot().len(), 1);
    assert!(store.usage_of("ghost").is_none());
}
