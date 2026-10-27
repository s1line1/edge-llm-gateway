//! registry 测试：注册/心跳归属/连接断开时的条目生命周期。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（P2-11）：注册条目随 [`Registration`] 的 Drop 摘除——**panic 展开也要摘**。
///
/// 为什么重要：`quic::handle_conn` 原来在末尾写一句 `remove_if_same`，panic 时那句不执行，
/// 条目就永久留在注册表里（本仓库没有 stale 清扫器），表现为 `hlmg_agents` 虚高 +
/// `/admin/agents` 幽灵条目。
#[tokio::test]
async fn registration_guard_removes_the_entry_on_drop_and_on_panic() {
    let reg = Registry::default();

    // 正常路径：守卫出作用域即摘除
    {
        let mut registration = Registration::new(&reg);
        let stable_id = reg.register(
            "home-1".into(),
            IP,
            vec!["m".into()],
            2,
            test_connection().await,
        );
        registration.note("home-1".into(), IP, stable_id);
        assert_eq!(reg.len(), 1);
    }
    assert_eq!(reg.len(), 0, "守卫 drop 必须摘掉条目");

    // panic 路径：展开过程中也要摘
    let conn = test_connection().await;
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut registration = Registration::new(&reg);
        let stable_id = reg.register("home-2".into(), IP, vec!["m".into()], 2, conn.clone());
        registration.note("home-2".into(), IP, stable_id);
        assert_eq!(reg.len(), 1);
        panic!("connection task blew up");
    }));
    assert!(panicked.is_err(), "前提：panic 发生了");
    assert_eq!(
        reg.len(),
        0,
        "panic 展开也必须摘掉条目（否则是永远删不掉的幽灵 agent）"
    );
}

/// 规格：同名**重新注册**只更新本连接记着的 `stable_id`——旧的那个对应不上当前条目，
/// 用旧 stable_id 摘除是 no-op（`remove_if_same` 会比对）。
#[tokio::test]
async fn registration_guard_refreshes_the_stable_id_of_a_re_registered_id() {
    let reg = Registry::default();
    let mut registration = Registration::new(&reg);
    let first = reg.register("x".into(), IP, vec!["m".into()], 2, test_connection().await);
    registration.note("x".into(), IP, first);
    assert_eq!(registration.owned_stable_id("x", IP), Some(first));
    let second = reg.register("x".into(), IP, vec!["m".into()], 2, test_connection().await);
    registration.note("x".into(), IP, second);
    assert_eq!(
        registration.owned_stable_id("x", IP),
        Some(second),
        "同名重新注册必须把记着的 stable_id 换成新的"
    );
    assert_eq!(reg.len(), 1);

    drop(registration);
    assert_eq!(reg.len(), 0, "最后一次注册的条目必须被摘掉");

    // 反向：只记着旧 stable_id 时，摘除不许误删新条目
    let mut stale = Registration::new(&reg);
    let fresh = reg.register("y".into(), IP, vec!["m".into()], 2, test_connection().await);
    stale.note("y".into(), IP, fresh.wrapping_sub(1)); // 一个不存在的 stable_id
    drop(stale);
    assert_eq!(reg.len(), 1, "stable_id 不匹配时不得摘除别人的条目");
}

/// 规格（记录 SL-P2-10）：**断开时摘掉本连接注册过的每一个 id**。
///
/// 只记最后一条时，`a1..aN` 里除 `aN` 之外的条目会永久留在表里（本仓库没有 stale 清扫器：
/// 心跳过期只是不再可路由），`hlmg_agents` 虚高、`/admin/agents` 出现没有对应进程的幽灵行。
///
/// 变异验证：把 `note` 退回"只留最后一个" ⇒ 本用例红（`left: 2, right: 0`）。
#[tokio::test]
async fn a_connection_removes_every_id_it_registered_when_it_drops() {
    let reg = Registry::default();
    let mut registration = Registration::new(&reg);
    let a1 = reg.register(
        "a1".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    registration.note("a1".into(), IP, a1);
    let a2 = reg.register(
        "a2".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    registration.note("a2".into(), IP, a2);
    assert_eq!(reg.len(), 2);

    drop(registration);
    assert_eq!(reg.len(), 0, "本连接注册过的两个 id 都必须被摘掉");
}

/// 防误删：本连接记着某个 id，但该 id 的条目**已被新连接接管**时，本连接退出不得摘掉它。
///
/// 两条连接都注册了 `a1`：后者的条目属于后者；前者 drop 时按 `stable_id` 比对发现对不上
/// ⇒ no-op，活着的条目不受影响（这正是"逐个摘"不能退化成"按 id 无条件删"的原因）。
#[tokio::test]
async fn an_exit_never_removes_an_id_another_connection_took_over() {
    let reg = Registry::default();
    let old = test_connection().await;
    let new = test_connection().await;

    let mut first_conn = Registration::new(&reg);
    let old_sid = reg.register("a1".into(), IP, vec!["m".into()], 2, old);
    first_conn.note("a1".into(), IP, old_sid);

    let mut second_conn = Registration::new(&reg);
    let new_sid = reg.register("a1".into(), IP, vec!["m".into()], 2, new);
    second_conn.note("a1".into(), IP, new_sid);
    assert_eq!(reg.len(), 1, "同名接管后表里仍只有一条");

    // 旧连接退出：它记的 old_sid 已经不对应当前条目 ⇒ 不许摘掉新的那条
    drop(first_conn);
    assert_eq!(reg.len(), 1, "接管之后的条目属于新连接，旧连接退出不得摘除");
    assert_eq!(
        reg.inner
            .read()
            .unwrap()
            .get(&AgentKey::new("a1", IP))
            .map(|e| e.stable_id),
        Some(new_sid)
    );

    // 新连接退出：这一次才摘掉
    drop(second_conn);
    assert_eq!(reg.len(), 0);
}

/// 规格（记录 SL-P2-10 的第 ② 部分）：每条连接的注册数**有上限**，但**刷新同名 id 不占额度**。
///
/// 上限的意义：`Register` 帧是对端自己发的，不设限时一条被拿下的连接可以插任意多条带
/// `models` 的条目。判定必须在 `register()` **之前**问（调用点在 `quic.rs`），否则被拒的那条
/// 已经插表、没人负责摘。
///
/// 变异验证：把 `accepts()` 改成恒 `true` ⇒ 本用例在"超限必须拒绝"那几行变红。
#[tokio::test]
async fn the_per_connection_cap_allows_refresh_but_rejects_new_ids() {
    let reg = Registry::default();
    let mut registration = Registration::new(&reg);

    // 还没注册任何 id 时先问一次：必须允许（否则第一条注册就被自己的上限挡住）
    assert!(registration.accepts("a1", IP));

    for n in 1..=MAX_REGISTRATIONS_PER_CONNECTION {
        let id = format!("a{n}");
        assert!(registration.accepts(&id, IP), "第 {n} 个新 id 必须被接受");
        let sid = reg.register(id.clone(), IP, vec!["m".into()], 2, test_connection().await);
        registration.note(id.clone(), IP, sid);
        // 刷新同名 id 永远允许，且不占新额度
        assert!(registration.accepts(&id, IP), "同名刷新不该被上限挡住");
    }
    assert_eq!(reg.len(), MAX_REGISTRATIONS_PER_CONNECTION);

    assert!(
        !registration.accepts("one-too-many", IP),
        "用满额度之后必须拒绝**新的** agent_id"
    );
    // 注意：已注册过的 id **不因满额而被拒**——它走的是覆盖，不占新额度。
    // （这一支正是"上限"与"刷新"的分界：上限只约束**不同**的 id 数。）
    assert!(
        registration.accepts("a1", IP),
        "已注册过的 id 必须仍然允许刷新，哪怕额度已满"
    );
    // 反过来说：`a1` 是注册过的，刷新它仍然允许
    let sid = reg.register(
        "a1".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    registration.note("a1".into(), IP, sid);
    assert!(registration.accepts("a1", IP));
}

/// 心跳的归属判据：**本连接注册过的每个 id** 都能交出 stable_id，别人的不能。
///
/// 只比"最后注册的那一个"时，同一条连接上早先注册的 id 的合法心跳会被误判成越权并丢弃
/// （或被反过来利用：让越权的心跳替别人的死条目续命）。
#[tokio::test]
async fn heartbeat_ownership_covers_every_registered_id_of_the_connection() {
    let reg = Registry::default();
    let mut registration = Registration::new(&reg);
    let a1 = reg.register(
        "a1".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    registration.note("a1".into(), IP, a1);
    let a2 = reg.register(
        "a2".into(),
        IP,
        vec!["m".into()],
        2,
        test_connection().await,
    );
    registration.note("a2".into(), IP, a2);

    assert_eq!(registration.owned_stable_id("a1", IP), Some(a1));
    assert_eq!(registration.owned_stable_id("a2", IP), Some(a2));
    assert_eq!(registration.owned_stable_id("someone-else", IP), None);
}

#[tokio::test]
async fn register_duplicate_replaces_and_len() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let id1 = reg.register("home-1".into(), IP, vec!["m".into()], 2, c1.clone());
    assert_eq!(reg.len(), 1);
    // 同名重复注册：旧连接被关闭，条目替换为新连接，长度仍为 1
    let c2 = test_connection().await;
    let id2 = reg.register("home-1".into(), IP, vec!["m".into()], 2, c2.clone());
    assert_eq!(reg.len(), 1);
    let entry = reg
        .inner
        .read()
        .unwrap()
        .get(&AgentKey::new("home-1", IP))
        .cloned()
        .unwrap();
    assert_ne!(id1, id2, "每次注册都必须拿到新的 stable_id");
    assert_eq!(entry.stable_id, id2, "条目应属于后注册的那条连接");
}

#[tokio::test]
async fn remove_if_same_guards_stable_id() {
    let reg = Registry::default();
    let c1 = test_connection().await;
    let c2 = test_connection().await;
    let id1 = reg.register("x".into(), IP, vec![], 4, c1.clone());
    let id2 = reg.register("x".into(), IP, vec![], 4, c2.clone()); // 条目换成 c2，c1 被关
                                                                   // 用旧连接的 stable_id 移除 → 不删除（条目现在属于 c2）
    reg.remove_if_same("x", IP, id1);
    assert_eq!(reg.len(), 1);
    // 用当前连接的 stable_id 移除 → 删除
    reg.remove_if_same("x", IP, id2);
    assert_eq!(reg.len(), 0);
    // 对不存在的 agent 移除 → 无害
    reg.remove_if_same("ghost", IP, id2);
}

/// 规格（SEC-005）：同 `agent_id` + 同来源 IP 在不同 tenant 下是两条独立条目，
/// 不会互相接管；tenant 路由只能拿到自己的那条。
#[tokio::test]
async fn same_agent_id_and_ip_coexist_in_different_tenants() {
    let reg = Registry::default();
    let a = reg.register_in_tenant(
        "tenant-a",
        "same".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );
    let b = reg.register_in_tenant(
        "tenant-b",
        "same".into(),
        IP,
        vec!["m".into()],
        4,
        test_connection().await,
    );
    assert_ne!(a, b);
    assert_eq!(reg.snapshot(Duration::from_secs(10)).len(), 2);
    assert_eq!(reg.count_for_tenant("tenant-a"), 1);
    assert_eq!(reg.count_for_tenant("tenant-b"), 1);

    let (entry_a, _slot_a) = reg
        .try_acquire_excluding_for_tenant("tenant-a", Duration::from_secs(10), "m", &[])
        .unwrap();
    assert_eq!(entry_a.stable_id, a);
    assert_eq!(entry_a.tenant_id(), "tenant-a");

    let (entry_b, _slot_b) = reg
        .try_acquire_excluding_for_tenant("tenant-b", Duration::from_secs(10), "m", &[])
        .unwrap();
    assert_eq!(entry_b.stable_id, b);
    assert_eq!(entry_b.tenant_id(), "tenant-b");
}
