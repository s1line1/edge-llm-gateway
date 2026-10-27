//! agent 测试：本机并发闸门：排队、节流与 `max_concurrency` 的端到端执行。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 规格（2026-09-25 复扫 E1）：**等闸门许可期间心跳仍必须被观察**。
///
/// `tokio::select!` 的分支体一旦 await，其它分支就不再被 poll。原先把 `g.acquire().await`
/// 直接写在 accept 分支体里，于是"闸门打满（许可被长 SSE 持有）"时心跳失败/panic 无人
/// 观察 ⇒ 连接不会被拆 ⇒ agent 自认连着、网关把每个请求判 503，两侧都没日志。
///
/// 控制点：许只有一个且已被占住，心跳任务已经结束。`acquire_slot` 必须**立刻**回
/// `HeartbeatDown`，而不是一直排队等许可。
#[tokio::test]
async fn waiting_for_a_slot_still_notices_a_dead_heartbeat() {
    let mut gate = ConcurrencyGate::new(1);
    let held = gate
        .as_mut()
        .expect("max_concurrency = 1 应当建闸门")
        .acquire()
        .await;
    // 已经结束的心跳任务（真实场景里是心跳失败/panic 之后退出的那个）。
    let mut hb = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

    let outcome = tokio::time::timeout(Duration::from_secs(2), acquire_slot(&mut gate, &mut hb))
        .await
        .expect("等许可时心跳结束必须立刻返回，而不是一直排队");
    assert!(
        matches!(outcome, SlotOutcome::HeartbeatDown),
        "应当报心跳结束以拆掉这条连接"
    );
    drop(held);
}

/// 对照：心跳**还活着**时，许可没空出来就不该返回（别把上面那条修成"总是立刻放弃"）。
#[tokio::test]
async fn waiting_for_a_slot_does_not_return_early_while_the_heartbeat_is_alive() {
    let mut gate = ConcurrencyGate::new(1);
    let held = gate.as_mut().unwrap().acquire().await;
    let mut hb = tokio::spawn(async { std::future::pending::<anyhow::Result<()>>().await });

    let raced =
        tokio::time::timeout(Duration::from_millis(200), acquire_slot(&mut gate, &mut hb)).await;
    assert!(raced.is_err(), "许可没空出来、心跳也没死 ⇒ 不该返回");

    hb.abort();
    drop(held);
}

/// 对照：有空位就发许可；`max_concurrency = 0`（不限）时没有闸门，返回 `None`。
#[tokio::test]
async fn a_free_slot_is_granted_and_no_gate_means_no_permit() {
    let mut gate = ConcurrencyGate::new(2);
    let mut hb = tokio::spawn(async { std::future::pending::<anyhow::Result<()>>().await });
    assert!(matches!(
        acquire_slot(&mut gate, &mut hb).await,
        SlotOutcome::Permit(Some(_))
    ));

    let mut no_gate: Option<ConcurrencyGate> = None;
    assert!(matches!(
        acquire_slot(&mut no_gate, &mut hb).await,
        SlotOutcome::Permit(None)
    ));
    hb.abort();
}

/// 规格（记录 P2-3）：**闸门满了要排队**，而不是把请求放过去压垮本地 LLM。
#[tokio::test]
async fn the_concurrency_gate_queues_instead_of_admitting() {
    let mut gate = ConcurrencyGate::new(1).expect("max=1 应当有闸门");
    let held = gate.acquire().await; // 唯一许可，立刻拿到
    let second = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut fut)
                .await
                .is_err(),
            "持有唯一许可时，第二次 acquire 不许成功"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("释放后应当立刻拿到许可")
    };
    assert_eq!(gate.queued(), 1, "等超 SLOT_WAIT_LOG_AFTER 要记一次排队");
    assert!(gate.last_log.is_some(), "排队要留下一条日志");
    drop(second);
}

/// 规格：`max_concurrency = 0` = **不限**（与网关侧 `0` 的语义一致）⇒ 不建闸门。
///
/// 这条钉的是"别把 0 当成 0 个许可"——那会让 agent 一个请求都不处理，比不设防更糟。
#[test]
fn a_zero_max_concurrency_builds_no_gate() {
    assert!(ConcurrencyGate::new(0).is_none(), "0 = 不限 ⇒ 没有闸门");
    assert!(ConcurrencyGate::new(4).is_some());
}

/// 规格：持续过载时**日志节流**（这个项目的日志单日 652MB），但排队计数照旧累加。
#[tokio::test]
async fn the_queue_log_is_throttled_while_the_counter_keeps_counting() {
    let mut gate = ConcurrencyGate::new(1).unwrap();
    let held = gate.acquire().await;
    let first_permit = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(150), &mut fut)
            .await
            .is_err());
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("第一次排队应当拿到")
    };
    let first_log = gate.last_log.expect("第一次排队必须打日志");
    let second_permit = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(150), &mut fut)
            .await
            .is_err());
        drop(first_permit);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("第二次排队应当拿到")
    };
    assert_eq!(gate.queued(), 2, "两次都超过阈值：计数要涨");
    assert_eq!(
        gate.last_log,
        Some(first_log),
        "同一个节流窗口内不得再打第二行"
    );
    drop(second_permit);
}

/// 规格（记录 P2-3，端到端）：**agent 自己执行它声明的 `max_concurrency`**。
///
/// 判据在上游侧：同时只有 1 个请求到达假上游。去掉 accept 路径上那道闸门后
/// `max_inflight` 会是 2——那正是"网关不守约（如配成 `0` = 不限）时，最多 1000 条并发
/// 全压进本地 LLM"的形状。判据放在上游而不是 agent 自己的计数上：agent 自述不算证据，
/// **真的只打了一个上游请求**才算。
#[tokio::test(flavor = "multi_thread")]
async fn the_agent_enforces_its_declared_max_concurrency_end_to_end() {
    use std::sync::atomic::Ordering;
    // 与 gateway 的 e2e 同一口径：让排队那条 WARN 在失败时看得见（rustls 的 debug 太吵）
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let (upstream, max_inflight, served) = counting_upstream(Duration::from_millis(200)).await;
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server_with_handle(&ca, srv_cert, srv_key).await;
    let mut cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    cfg.max_concurrency = 1;
    cfg.upstream_base = upstream;
    // 心跳周期放大：本测试只活几百毫秒，别让"没人回心跳"把连接拆了（那是另一条测试的事）
    cfg.heartbeat_interval = Duration::from_secs(30);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));

    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    // 两条请求流几乎同时发：闸门只该放一条过去。
    // 两个半边都必须**持有着**（第一版两个坑都踩了）：
    // ① drop `recv` 会停掉该方向，agent 写响应时报 "The Stream ID which was referenced is
    //    invalid"；
    // ② drop `send` 会给对端发 FIN —— agent 那边把"流结束"当**取消**，于是根本不发上游请求
    //    （`handle_stream` 直接 Ok 返回，而我们还在等下家服务）。
    let mut keep_recv = Vec::new();
    let mut keep_send = Vec::new();
    for request_id in 0..2u64 {
        let stream = gateway.open_bidirectional_stream().await.expect("开流");
        let (recv, mut send) = stream.split();
        keep_recv.push(recv);
        write_frame(
            &mut send,
            &Frame::ProxyRequest {
                request_id,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers: vec![],
                body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
            },
        )
        .await
        .expect("写请求帧");
        keep_send.push(send);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while served.load(Ordering::SeqCst) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "两个请求没有都被服务：served={}",
            served.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        max_inflight.load(Ordering::SeqCst),
        1,
        "agent 必须自己执行 max_concurrency=1（没有闸门时这里会是 2）"
    );
    drop(keep_send);
    drop(keep_recv);
    task.abort();
}
