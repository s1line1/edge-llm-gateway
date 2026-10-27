//! registry 测试：并发占位（CAS）与排除重试。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 契约：**换 agent 重试时必须排除刚失败的那条连接**。
///
/// 否则"重试"会再次选中同一条坏连接，等于没重试——这在生产表现为"重试了但还是
/// 502"，而日志里看不出原因。
#[tokio::test]
async fn try_acquire_excluding_skips_the_failed_connection() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    let id1 = reg.register("a".into(), IP, vec!["*".into()], 4, c1.clone());
    let id2 = reg.register("b".into(), IP, vec!["*".into()], 4, c2.clone());
    let stale = Duration::from_secs(10);

    // 不排除任何连接：两次选取都会命中某个候选（不关心是哪个）
    assert!(reg.try_acquire(stale, "m").is_ok());

    // 排除 a → 只能选到 b
    let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id1]).unwrap();
    assert_eq!(e.stable_id, id2, "排除 a 后应选中 b");

    // 排除 b → 只能选到 a
    let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id2]).unwrap();
    assert_eq!(e.stable_id, id1, "排除 b 后应选中 a");

    // 两条都排除 → 候选**全被本轮排除**，这与"没人可用"是两件事（复扫 B1）：
    // 混成同一个 `NoAgent`，单 agent 忙时就会对外报 503 `no edge available`。
    assert!(matches!(
        reg.try_acquire_excluding(stale, "m", &[id1, id2]),
        Err(AcquireError::AllExcluded)
    ));

    // 对照：注册表里真的没人 → `NoAgent`（别把上面那条修成"什么都报 AllExcluded"）。
    let empty = Registry::default();
    assert!(matches!(
        empty.try_acquire_excluding(stale, "m", &[]),
        Err(AcquireError::NoAgent)
    ));
}

#[tokio::test]
async fn try_acquire_spreads_load_and_capacity() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    reg.register("a".into(), IP, vec!["*".into()], 1, c1.clone());
    reg.register("b".into(), IP, vec!["*".into()], 1, c2.clone());

    // 两个容量各 1 的 agent：连续两个请求应命中不同 agent
    let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    assert_ne!(e1.stable_id, e2.stable_id);
    // 全满 → AtCapacity
    assert!(matches!(
        reg.try_acquire(Duration::from_secs(10), "qwen2.5"),
        Err(AcquireError::AtCapacity)
    ));
    drop(s1);
    drop(s2);
    // 槽位释放后恢复
    assert!(reg.try_acquire(Duration::from_secs(10), "qwen2.5").is_ok());
}

/// 规格：`max_concurrency == 0` = 不限（永远拿得到槽位），但**计数仍然必须真实**。
///
/// `0` 只关掉"准入上限"这一件事；`inflight` 同时还是另外三处的输入：
/// 开流超时的忙/死（[`Entry::open_timeout_is_fatal`]）、摘除时"是否还有别人在途"
/// （[`Registry::evict`] 的 `inflight <= 1`）、以及负载排序（`try_acquire_excluding`
/// 的 `sort_by_key`）。只减不加会让 `AtomicU32` **下溢回绕成 4294967295**：开流判据
/// 永久失效、每次摘除都白等满宽限期、这台 agent 永远排最后、`/admin/agents` 显示天文数字
/// （已记录：`docs/PROJECT_SCAN.md` P1-3）。
#[tokio::test]
async fn max_concurrency_zero_always_acquires_and_still_counts_inflight() {
    let reg = Registry::default();
    let conn = test_connection().await;
    reg.register("z".into(), IP, vec!["*".into()], 0, conn.clone()); // 0 = 不限

    // ① 只减不加 → 下溢：拿 5 次再**全部归还**，计数必须回到 0。
    //    在未修的实现里这里会读到 4294967295（`AtomicU32` 回绕），正是 P1-3 记录的形态。
    {
        let mut slots = Vec::new();
        for _ in 0..5 {
            let (_entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
            slots.push(slot);
        }
        drop(slots);
    }
    assert_eq!(
        reg.snapshot(Duration::from_secs(10))[0].inflight,
        0,
        "拿 5 次再全部归还后必须回到 0；只减不加会下溢成 4294967295"
    );

    // ② 而且过程里必须如实累加：不限并发不等于不计数
    let mut slots = Vec::new();
    for expected in 1..=5u32 {
        let (entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        slots.push(slot);
        assert_eq!(
            entry.inflight.load(Ordering::Relaxed),
            expected,
            "不限并发也必须如实计数：开流判据、摘除判据、负载排序都读这个数"
        );
    }
    assert_eq!(
        reg.snapshot(Duration::from_secs(10))[0].inflight,
        5,
        "运维看到的在途数同样要真实"
    );

    drop(slots);
    assert_eq!(
        reg.snapshot(Duration::from_secs(10))[0].inflight,
        0,
        "最后一次释放后必须回到 0；下溢会变成 4294967295"
    );
}

/// 规格（S2-3）：唯一能服务该模型的 agent 被本轮 exclude，但池里还有别的模型的 agent 时，
/// 必须报"忙"（AllExcluded → 429），不能报"模型不存在"（NoModel → 404）。
#[tokio::test]
async fn heterogeneous_pool_reports_all_excluded_when_sole_model_agent_is_excluded() {
    let reg = Registry::default();
    let qwen = reg.register(
        "qwen".into(),
        IP,
        vec!["qwen".into()],
        4,
        test_connection().await,
    );
    reg.register(
        "llama".into(),
        IP,
        vec!["llama".into()],
        4,
        test_connection().await,
    );
    assert!(matches!(
        reg.try_acquire_excluding(Duration::from_secs(10), "qwen", &[qwen]),
        Err(AcquireError::AllExcluded)
    ));
}
