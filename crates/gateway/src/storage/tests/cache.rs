//! storage 测试：已验证身份缓存（单飞、TTL、吊销即时生效）。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享导入。

use super::*;
use crate::storage::hash::CheapArgon2;
use std::sync::{Arc, Barrier};

/// 并发压同一个 token；返回 (argon2 调用次数增量, 全部请求的结果)。
/// `cache_max = 0` 时代表"关闭缓存"（旧行为）。
fn hammer(store: &Storage, token: &str, threads: usize) -> (usize, Vec<bool>) {
    let before = store.argon2_runs();
    let barrier = Arc::new(Barrier::new(threads));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let store = store.clone();
        let token = token.to_string();
        let barrier = barrier.clone();
        let results = results.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let ok = store.authorize(&token);
            results.lock().unwrap().push(ok);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let calls = store.argon2_runs() - before;
    let out = results.lock().unwrap().clone();
    (calls, out)
}

#[test]
fn concurrent_same_token_hashes_once() {
    let _cheap = CheapArgon2::install();
    // 这是把内存峰值从 `并发数 × 19MiB` 压到 `1 × 19MiB` 的核心契约
    let store = Storage::new(None);
    let key = store.create("one".into()).unwrap();
    let (calls, results) = hammer(&store, &key.plaintext, 8);
    assert_eq!(calls, 1, "同一个 token 的 8 个并发请求只应跑 1 次 argon2");
    assert!(results.iter().all(|ok| *ok), "所有并发请求都应当通过");
}

#[test]
fn warm_token_never_hashes_again() {
    let _cheap = CheapArgon2::install();
    let store = Storage::new(None);
    let key = store.create("warm".into()).unwrap();
    assert!(store.authorize(&key.plaintext)); // 首次：算一次（create 那次不算）
    let before = store.argon2_runs();
    for _ in 0..50 {
        assert!(store.authorize(&key.plaintext));
    }
    assert_eq!(store.argon2_runs() - before, 0, "命中缓存不应再跑 argon2");
    let (hits, _) = store.verified_counters();
    assert!(hits >= 50, "命中计数应当累加，实际 {hits}");
}

#[test]
fn disabled_cache_keeps_old_behaviour() {
    let _cheap = CheapArgon2::install();
    // cache_max = 0 → 每个请求都完整校验（与改造前语义一致）
    let key = Storage::with_verified(None, 0, DEFAULT_VERIFIED_TTL);
    let token = key.create("nocache".into()).unwrap().plaintext;
    let before = key.argon2_runs();
    for _ in 0..3 {
        assert!(key.authorize(&token));
    }
    let off = key.argon2_runs() - before;

    // 对照：开启缓存时，首个请求填缓存（1 次 argon2），之后不再跑
    let warm = Storage::new(None);
    let token2 = warm.create("cached".into()).unwrap().plaintext;
    assert!(warm.authorize(&token2)); // 预热：这一次是缓存未命中
    let before2 = warm.argon2_runs();
    for _ in 0..3 {
        assert!(warm.authorize(&token2));
    }
    let on = warm.argon2_runs() - before2;

    assert_eq!(off, 3, "关闭缓存时每请求各跑一次，实际 {off}");
    assert_eq!(on, 0, "开启缓存且已预热后不应再跑 argon2，实际 {on}");
}

/// 规格：**关闭缓存时，每一次校验都要计入"真跑了 argon2"**（评估 §6 的指标口径）。
///
/// `hlmg_key_verify_misses_total` 的 HELP 写的是 "Key verifications that ran argon2"，
/// 而它的自增点原先在 `put`——缓存关闭时走的是"每请求完整校验"那一支，**根本不经过 `put`**。
/// 于是这个计数器在 `verified_cache_max: 0` 下恒为 0：每请求都在跑 19MiB argon2，
/// 而运维在唯一会持续烧 argon2 的配置里看不到任何负载。
///
/// （注意：错 token 走不到这里——`sha256` 不同 ⇒ runtime 查不到 ⇒ **按设计不跑 argon2**，
/// 既有单测 `authorize_rejects_unknown_lookup_without_argon2` 钉着这一点，所以那种负载
/// 本来就不该被算成 argon2 次数。）
#[test]
fn counter_counts_argon2_runs_when_the_cache_is_disabled() {
    let _cheap = CheapArgon2::install();
    let store = Storage::with_verified(None, 0, DEFAULT_VERIFIED_TTL);
    let token = store.create("nocache-metric".into()).unwrap().plaintext;
    for _ in 0..3 {
        assert!(store.authorize(&token));
    }
    let (hits, misses) = store.verified_counters();
    assert_eq!(hits, 0, "缓存关闭时不可能命中");
    assert_eq!(
        misses, 3,
        "3 次校验 = 3 次 argon2，必须都计入（修好前这里是 0）"
    );
}

#[test]
fn revoke_takes_effect_immediately() {
    let _cheap = CheapArgon2::install();
    // 缓存**不得**延长吊销窗口：delete 后必须立刻 401
    let store = Storage::new(None);
    let key = store.create("revoke".into()).unwrap();
    assert!(store.authorize(&key.plaintext));
    assert!(store.authorize(&key.plaintext)); // 已进缓存
    assert!(store.delete(&key.record.id).unwrap());
    assert!(
        !store.authorize(&key.plaintext),
        "吊销后必须立即失效（不允许缓存放行）"
    );
}

#[test]
fn credential_version_bump_invalidates_cache() {
    let _cheap = CheapArgon2::install();
    // 模拟"改 key 但不 bump 版本"以外的正确路径：bump 之后旧缓存条目必须失效
    let store = Storage::new(None);
    let key = store.create("bump".into()).unwrap();
    assert!(store.authorize(&key.plaintext));
    let before = store.argon2_runs();
    assert!(store.authorize(&key.plaintext));
    assert_eq!(store.argon2_runs() - before, 0, "命中缓存");

    // 直接改记录里的 cred_version（等价于"凭据变更走了正确路径"）
    {
        let mut runtime = store.inner.runtime.write().unwrap();
        let rec = runtime.get_mut(&key.record.lookup).unwrap();
        rec.cred_version += 1;
    }
    let before = store.argon2_runs();
    assert!(
        store.authorize(&key.plaintext),
        "版本变了应当重新校验，而不是拒绝"
    );
    assert_eq!(
        store.argon2_runs() - before,
        1,
        "版本变更后必须重跑一次 argon2"
    );
}

#[test]
fn expired_entry_is_revalidated() {
    let _cheap = CheapArgon2::install();
    // TTL 到期后重算（不改变"吊销即时"这条，只影响多久重付一次 argon2 的钱）
    let store = Storage::with_verified(None, DEFAULT_VERIFIED_MAX, Duration::from_millis(50));
    let key = store.create("ttl".into()).unwrap();
    assert!(store.authorize(&key.plaintext));
    std::thread::sleep(Duration::from_millis(80));
    let before = store.argon2_runs();
    assert!(store.authorize(&key.plaintext));
    assert_eq!(store.argon2_runs() - before, 1, "TTL 到期应重算一次");
}

#[test]
fn cache_is_bounded_and_never_stores_plaintext() {
    let _cheap = CheapArgon2::install();
    let store = Storage::with_verified(None, 2, DEFAULT_VERIFIED_TTL);
    let mut tokens = Vec::new();
    for i in 0..5 {
        let k = store.create(format!("k{i}")).unwrap();
        assert!(store.authorize(&k.plaintext));
        tokens.push(k.plaintext);
    }
    assert!(
        store.inner.verified.len() <= 2,
        "缓存条目数不得超过配置上限，实际 {}",
        store.inner.verified.len()
    );
    // 缓存**只键于 sha256(token)**：键全 64 位十六进制，且没有任何一个是明文 token
    let keys = store.inner.verified.keys();
    assert_eq!(keys.len(), store.inner.verified.len());
    assert!(
        keys.iter()
            .all(|k| k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit())),
        "缓存键必须是 sha256 十六进制，实际 {keys:?}"
    );
    for t in &tokens {
        assert!(
            !keys.contains(t),
            "缓存不得以明文 token 为键：{t} 出现在 {keys:?}"
        );
    }
}

#[test]
fn wrong_token_still_rejected_with_cache() {
    let _cheap = CheapArgon2::install();
    // 命中路径不得绕过校验：拿别人的 token 永远进不去
    let store = Storage::new(None);
    let good = store.create("good".into()).unwrap();
    assert!(store.authorize(&good.plaintext));
    assert!(!store.authorize("sk-deadbeef"));
    assert!(!store.authorize(&format!("{}x", good.plaintext)));
}
