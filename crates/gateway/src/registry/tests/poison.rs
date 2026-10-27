//! registry 测试：中毒锁：一次 panic 不得让注册/选路永久不可用。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（评估 §7 步骤 6 的结转项 A / registry 评估 M2）：**表锁中毒后注册与选路
/// 不能全挂**。
///
/// 表只是内存映射，守卫内 panic 不会写坏它；而 `.read().unwrap()` 会把一次 panic
/// 放大成"之后每个请求都无法选路"——进程活着、指标还在跑，但全站 503。
#[tokio::test]
async fn a_poisoned_registry_lock_does_not_take_routing_down() {
    let reg = Registry::default();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = reg.inner.write().unwrap();
        panic!("poison the registry table");
    }));
    assert!(poisoned.is_err(), "前提：panic 发生了");
    assert!(reg.inner.is_poisoned(), "前提：锁中毒了");

    let conn = test_connection().await;
    reg.register("home-1".into(), IP, vec!["m".into()], 2, conn);
    assert_eq!(reg.len(), 1, "中毒后仍应能注册");
    let (_entry, _slot) = reg
        .try_acquire(Duration::from_secs(10), "m")
        .expect("中毒后仍应能选路");
}
