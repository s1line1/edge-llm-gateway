//! registry 测试：失败记账、busy/dead 判据与摘除。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 契约：**摘除时若还有别的在途请求，不得立刻关闭连接**。
///
/// 那些请求已经把请求帧完整送达 agent、模型正在生成——它们不满足"建立阶段失败"
/// 的重试条件，被打断就是纯损失（客户花了算力还拿不到结果）。所以摘除只做
/// "移出路由"，连接等 drain 完（或过宽限期）再关。
///
/// 反过来，若只剩当前这一个失败请求占槽位，立刻关闭是安全的——而且要立刻关，
/// 好让 agent 察觉并重连，别变回僵尸。
#[tokio::test]
async fn eviction_defers_close_while_other_requests_are_in_flight() {
    let stale = Duration::from_secs(10);

    // 情形一：还有别的在途请求（这里手工把 inflight 顶到 3）
    let reg = Registry::default();
    let conn = test_connection().await;
    let id = reg.register("busy".into(), IP, vec!["*".into()], 8, conn.clone());
    let (_e, g1) = reg.try_acquire(stale, "m").unwrap();
    let (_e2, g2) = reg.try_acquire(stale, "m").unwrap();
    let (_e3, g3) = reg.try_acquire(stale, "m").unwrap();
    assert_eq!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 1 }
    );
    assert_eq!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 2 }
    );
    match reg.evict(id, EvictCause::OpenTimeout, GRACE) {
        EvictOutcome::RemovedClosedLater { inflight } => {
            assert!(inflight >= 3, "应报出当时的在途数，实际 {inflight}")
        }
        other => panic!("还有在途请求时不应立即关闭连接，实际 {other:?}"),
    }
    assert_eq!(reg.len(), 0, "无论是否延迟关闭，条目都必须先移出路由");
    drop((g1, g2, g3));

    // 情形二：只剩当前请求 → 立即关闭
    let reg2 = Registry::default();
    let conn2 = test_connection().await;
    let id2 = reg2.register("idle".into(), IP, vec!["*".into()], 8, conn2.clone());
    let (_e4, _g4) = reg2.try_acquire(stale, "m").unwrap();
    assert!(matches!(
        reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { .. }
    ));
    assert!(matches!(
        reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { .. }
    ));
    assert_eq!(
        reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::RemovedClosed
    );
}

/// 契约：**单次隧道操作超时不得摘除条目**（高并发下那是排队假象），
/// 连续超时达阈值才摘除；任何一次成功都要清零计数。
///
/// 实测背景：768 并发下第一次超时就把条目摘掉，而连接完好、agent 不知情，
/// 于是注册表里没有它、请求全部 503（占 92.6%），agent 因为心跳仍能通而永远
/// 不重连 —— "僵尸"态。
#[tokio::test]
async fn tunnel_timeouts_evict_only_after_consecutive_failures() {
    let reg = Registry::default();
    let conn = test_connection().await;
    let id = reg.register("t".into(), IP, vec!["*".into()], 4, conn.clone());

    // 前两次超时：条目保留
    assert!(matches!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 1 }
    ));
    assert_eq!(reg.len(), 1);
    assert!(matches!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 2 }
    ));
    assert_eq!(reg.len(), 1);
    // 中途一次成功 → 计数清零，重新从头累计
    reg.note_tunnel_op_ok(id);
    assert!(matches!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 1 }
    ));
    assert_eq!(reg.len(), 1);
    // 再来两次（累计到 3）→ 摘除；此时只有本请求占槽位 → 立即关闭
    assert!(matches!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::BelowThreshold { .. }
    ));
    assert!(matches!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::RemovedClosed
    ));
    assert_eq!(reg.len(), 0);
    // 已摘除后再调用：无害
    assert_eq!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::NotFound
    );
}

/// 规格：**每一种失败原因各有自己的"连续"计数**。
///
/// 计数混在一起时，三种**不同**的轻微失败会凑满同一个阈值，把一条其实健康的连接摘掉；
/// 而且任何一种失败达到阈值后，另一种失败的"连续"语义就被无声地改写了。云端实测里
/// "开流超时"与"响应头超时"是两条独立的事故线（`routing.rs:122-125`、
/// `head_timeout.rs:3-9`），它们的阈值不能互相充值。
#[tokio::test]
async fn strike_counters_are_independent_per_cause() {
    let reg = Registry::default();
    let conn = test_connection().await;
    let id = reg.register("t".into(), IP, vec!["*".into()], 4, conn.clone());

    // 两种失败各记两次：各自都还差一次，谁都不该摘除
    for expected in 1..=2 {
        assert!(
            matches!(
                reg.evict(id, EvictCause::OpenTimeout, GRACE),
                EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
            ),
            "开流超时应独立计数到 {expected}"
        );
        assert!(
            matches!(
                reg.evict(id, EvictCause::HeadTimeout, GRACE),
                EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
            ),
            "响应头超时应独立计数到 {expected}"
        );
    }
    assert_eq!(
        reg.len(),
        1,
        "2 次开流 + 2 次响应头 = 4 次失败，但没有任何**一种**达到阈值"
    );

    // 第三种原因也从 1 开始，不受前两种影响
    assert!(matches!(
        reg.evict(id, EvictCause::TunnelWriteFailed, GRACE),
        EvictOutcome::BelowThreshold { consecutive: 1 }
    ));

    // 只有某一种真正连续到阈值才摘除
    assert_eq!(
        reg.evict(id, EvictCause::OpenTimeout, GRACE),
        EvictOutcome::RemovedClosed
    );
    assert_eq!(reg.len(), 0);
}

/// 规格：**"开流超时"不等于"连接已死"**。
///
/// `open_bidirectional_stream()` 在连接级流额度排满时会排队等回收，所以超时有两种
/// 成因：对端死了（该摘除），或对端忙、在途已经顶到承载上限（正常背压，摘除就是
/// 把局部过载放大成全站不可用）。
///
/// 云端实测的代价（2026-09-17，4 agent、768 并发）：一律摘除 → `tunnel open timed out`
/// 9345 次、健康 agent 被关掉重连 → 单次 30s 压测 `registry-empty` +6835 → 全量 503。
#[tokio::test]
async fn open_timeout_is_fatal_only_when_the_connection_is_not_at_capacity() {
    let reg = Registry::default();
    let conn = test_connection().await;
    reg.register("busy".into(), IP, vec!["*".into()], 1, conn.clone());
    let (entry, guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

    // 在途 1 > 0：没到这条连接的上限（max_concurrency = 1 时 1 就是满）
    entry.inflight.store(0, Ordering::Relaxed);
    assert!(
        entry.open_timeout_is_fatal(1024),
        "没有任何在途请求却开不出流 = 连接确实坏了，必须摘除"
    );

    // 在途 1 = max_concurrency：额度排满后的排队超时是背压，不是死亡
    entry.inflight.store(1, Ordering::Relaxed);
    assert!(
        !entry.open_timeout_is_fatal(1024),
        "在途已达声明的 max_concurrency → 超时是排队等额度，不能摘除健康连接"
    );
    drop(guard);

    // 声明不限并发（max_concurrency = 0）时，上限就是端点流额度
    let conn2 = test_connection().await;
    reg.register("unbounded".into(), IP, vec!["*".into()], 0, conn2);
    let (entry2, _g2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    assert_eq!(entry2.agent_id, "unbounded");
    entry2.inflight.store(3, Ordering::Relaxed);
    assert!(
        entry2.open_timeout_is_fatal(4),
        "在途 3 < 额度 4 → 还有额度却开不出流 = 坏连接"
    );
    entry2.inflight.store(4, Ordering::Relaxed);
    assert!(
        !entry2.open_timeout_is_fatal(4),
        "在途 = 额度 → 超时是额度排队，不是死亡"
    );

    // 配置不一致（agent 声明 256 > 端点额度 100）：以更小的那个为准，
    // 否则"忙"会被判成"死"，又回到摘除健康 agent 的老路。
    let conn3 = test_connection().await;
    reg.register("over-declared".into(), IP, vec!["*".into()], 256, conn3);
    let (entry3, _g3) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    assert_eq!(entry3.agent_id, "over-declared");
    entry3.inflight.store(99, Ordering::Relaxed);
    assert!(entry3.open_timeout_is_fatal(100));
    entry3.inflight.store(100, Ordering::Relaxed);
    assert!(
        !entry3.open_timeout_is_fatal(100),
        "额度先于容量耗尽时，超时同样是背压（这正是要告警的配置不一致）"
    );
}

/// 规格：**响应头超时要能区分"最近还在干活"与"真的没有了"**（判据第一层）。
///
/// 这条判据是"链路被堵住 → 健康 agent 被摘除 → 全量 503"的唯一出口：窗口内有过成功响应头
/// 就只是慢（不摘除），窗口内一次都没有才算死。窗口本身由 `4 × head_timeout` 派生（见 `state.rs`）。
/// 第二层（对端还活着时的延长）在下面那条用例里。
///
/// ⚠️ 时间基准 `epoch()` 是**首次使用时才创建**的，所以测试进程刚起来时 `now_millis()`
/// 接近 0——不能用"把时间戳减去 10 秒"来伪造沉默（会被 saturating 压到 0）。这里改为
/// 真实小睡几毫秒、再把窗口压到 1ms 来跨过边界，避免依赖时间基准的起点。
#[tokio::test]
async fn head_timeout_is_fatal_only_after_a_window_of_total_silence() {
    let reg = Registry::default();
    let conn = test_connection().await;
    reg.register("alive".into(), IP, vec!["*".into()], 4, conn);
    let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
    // 本用例只考第一层：`stuck_after` 给 0（对端活着也延长不了），对端也**从未心跳**。
    let only_window = |window: Duration| HeadSilence {
        window,
        peer_alive_window: Duration::from_secs(15),
        stuck_after: Duration::ZERO,
    };

    // ① 刚注册但**从未回过响应头** → 没有"只是慢"的证据 → 判死
    //    （否则注册后从不回包的坏隧道会被宽限一个窗口才摘除）
    assert!(
        entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
        "从未收到过响应头时不该被当成「只是慢」"
    );

    // ② 收到过响应头 → 仍在窗口内 → 只是慢（这条是判据最该避免的误判）
    reg.note_tunnel_op_ok(entry.stable_id());
    assert!(
        !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
        "刚刚回过响应头的隧道被判定为死"
    );

    // ③ 沉默 50ms 之后：窗口 1ms → 判死；窗口 60s → 仍只是慢。
    //    同一次沉默、只改窗口就翻转结论，说明判据确实由"沉默时长 vs 窗口"决定。
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
        "沉默 50ms > 窗口 1ms → 必须判死（否则坏连接永远摘不掉）"
    );
    assert!(
        !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
        "沉默 50ms < 窗口 60s → 只是慢，不能判死"
    );

    // ④ 期间只要再成功收到一次响应头，窗口重新开始计时
    reg.note_tunnel_op_ok(entry.stable_id());
    assert!(
        !entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
        "刚回过响应头就该立刻回到「只是慢」，否则连续计数的语义不成立"
    );
}

/// 规格（判据第二层，评估 §5 H2）：**对端还在说话时，窗口过了也不判死**——
/// 均匀慢流量（所有请求都慢过 `head_timeout`）不能摘掉一条活着的 agent。
///
/// 为什么必须单独钉：`last_head_ok` 的唯一刷新点就是成功响应头，所以"所有请求都慢"时
/// 没有任何一次成功能刷新它，第一层必然走到"判死"。这一层用"收到过心跳"作为对端活着的
/// 证据把容忍度延长到 `stuck_after`（一条请求的寿命）。
#[tokio::test]
async fn head_silence_is_tolerated_while_the_peer_keeps_heartbeating() {
    let reg = Registry::default();
    let conn = test_connection().await;
    let alive_id = reg.register("slow-but-alive".into(), IP, vec!["*".into()], 4, conn);
    let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

    // 先让它"回过一次响应头"，然后沉默 50ms（把窗口压到 1ms 来跨过边界，同上面的技巧）。
    reg.note_tunnel_op_ok(entry.stable_id());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ① 对端**从未心跳** → 只有第一层 → 判死（这就是既有 e2e 钉的"裸 agent"形态）
    assert!(
        entry.head_timeout_is_fatal(HeadSilence {
            window: Duration::from_millis(1),
            peer_alive_window: Duration::from_secs(15),
            stuck_after: Duration::from_secs(120),
        }),
        "对端从未说过话时不该获得延长"
    );

    // ② 收到心跳 → 对端还活着 → 沉默没超过 stuck_after → **不判死**（H2 要的就是这一格）
    assert!(reg.heartbeat_if_same("slow-but-alive", IP, alive_id));
    let alive = HeadSilence {
        window: Duration::from_millis(1),
        peer_alive_window: Duration::from_secs(15),
        stuck_after: Duration::from_secs(120),
    };
    assert!(
        !entry.head_timeout_is_fatal(alive),
        "对端还在心跳、沉默也远没到一条请求的寿命，不该判死（均匀慢流量误摘）"
    );

    // ③ 但静默超过 stuck_after 就判死：心跳正常、数据面却长时间一声不响 = 卡死，
    //    不能让它永远留在路由里（否则每个请求都白等一次 head_timeout）。
    assert!(
        entry.head_timeout_is_fatal(HeadSilence {
            stuck_after: Duration::from_millis(1),
            ..alive
        }),
        "沉默超过一条请求的寿命后必须判死，否则数据面卡死的连接永远摘不掉"
    );

    // ④ 心跳也停了 → 回到"只看窗口"。
    //    用 `peer_alive_window = 0` 表示"心跳一律不算新鲜"，比"压到 1ms 再睡几毫秒"确定：
    //    刚发出的心跳在同一个毫秒里 `since == 0`，1ms 的窗口仍然算新鲜（这里踩过一次）。
    assert!(
        entry.head_timeout_is_fatal(HeadSilence {
            peer_alive_window: Duration::ZERO,
            ..alive
        }),
        "心跳过期后不该再享有延长"
    );
}
