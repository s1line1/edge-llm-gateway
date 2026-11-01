//! 同名同来源的**接管必须优雅**（2026-10-16，D3）：旧连接上的在途请求不能被掐断。
//!
//! 背景：注册表的键是 `(agent_id, peer_ip)`，所以同一个节点重连（同名同来源）会**接管**旧条目
//! ——新连接入表、旧连接移出路由。改造前这一步是**立刻** `close()`，而那条连接上往往还有
//! "请求帧已完整送达上游、模型正在生成"的在途请求；立刻关掉就是纯损失（客户花了算力还拿不到
//! 结果）。这正是 `evict_close` 这个模块存在的理由，只是接管路径原先没走它。
//!
//! 这条 e2e 是**真正的验收判据**：注册表的单测只能钉住"关闭时机"这个纯逻辑，而"在真实 QUIC
//! 栈上，一个正在流式返回的请求能不能活过接管"只有这里能证明。
//!
//! 变异验证：把 `register_with_grace` 里的 `inflight == 0` 分支改回 `<= 1`（或直接
//! `old_conn.close()`）⇒ 本用例必须变红（客户端拿到截断/错误而不是完整响应体）。

use std::time::Duration;

use super::common::*;

#[tokio::test]
#[serial]
async fn e2e_takeover_drains_the_in_flight_request_instead_of_cutting_it() {
    // 宽限给足：接管发生在请求开始后不久，而 mock 的正文停顿是 `SLOW_BODY_STALL`(3s)，
    // 所以宽限必须明显大于 3s——否则测的是"宽限到期强关"而不是"drain 到归零"。
    // `start_stack*` 不交出证书材料（那是 TestGateway 的字段），所以这里自己起一个测试网关，
    // 好把 `certs` 拿在手上签第二条（接管用的）agent 连接。
    let t = start_gateway(|o| {
        o.evict_close_grace = Duration::from_secs(30);
        // `/system/agents` 只在配了 admin_token 时才注册（`http/mod.rs`）——本用例要读
        // `inflight` 确认请求真的在途，所以必须开。
        o.admin_token = Some("admin-token".into());
    })
    .await;
    let mock_addr = start_mock_llm("mock-llm").await;
    let _agent = t
        .certs
        .agent(&t.gw, "test-agent", &["mock-llm"], mock_addr, 4, true);
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;
    let TestGateway {
        gw,
        key,
        base,
        certs,
        ..
    } = t;

    // ① 发一个会**停在途**的请求：/v1/slow_body 立刻回响应头，正文 3s 后才出第一块。
    let base_for_req = base.clone();
    let key_for_req = key.clone();
    let inflight = tokio::spawn(async move {
        let client = test_client_within(Duration::from_secs(30));
        client
            .post(format!("{base_for_req}/v1/slow_body"))
            .header("Authorization", format!("Bearer {key_for_req}"))
            .json(&serde_json::json!({"model": "mock-llm", "stream": true}))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    });

    // 让请求真正进入在途（否则接管可能发生在它之前，测的就不是接管了）
    wait_for_any_agent_inflight(&base, 1).await;

    // ② 同名同来源重连 → 接管。新连接**会真正服务**请求（辅助函数跑的是
    //    `agent::stream::handle_stream`），所以"旧连接被 drain"与"新连接能接手"两边都成立。
    let _second = spawn_serving_agent(&gw, &certs, "test-agent", mock_addr, 4).await;
    wait_for_agent_count(&gw, 1, "接管后条目数不变", Duration::from_secs(5)).await;

    // ③ 在途请求必须**完整拿到响应体**——这正是"旧连接没有被立刻关掉"的证明。
    let body = bounded("takeover 期间的在途请求", inflight)
        .await
        .expect("请求必须成功拿到响应（接管不得掐断在途请求）")
        .expect("响应体必须可读（不是被截断的流）");
    assert!(
        body.contains("[DONE]"),
        "响应体必须完整（含 [DONE]），实际拿到：{body:?}"
    );
}

/// **两个不同来源 IP 的同一 `agent_id` 在真实 wire 上并存**（D1 的端到端验收）。
///
/// 为什么这条值得单独存在：注册表单测已经钉住了"两个不同 IP ⇒ 两条独立条目"这个**纯逻辑**，
/// 但"网关在真实 QUIC 栈上确实能**观测到两个不同的对端 IP**"是另一回事——它取决于监听是不是
/// 双栈、以及 `Handle::remote_addr()` 报回来的是什么。这条用例把两者接起来。
///
/// 造法（`research.md` R3 的实测结论）：macOS 没有 `127.0.0.2` 别名（`bind` 报 `Errno 49`），
/// 所以第二个来源用 **IPv6 回环**。网关绑 `[::]:0`（双栈，macOS UDP 默认 `IPV6_V6ONLY=0`），
/// 一个客户端从 `127.0.0.1` 接入、另一个从 `[::1]` 接入——服务端看到 `127.0.0.1` 与 `::1`，
/// 是两个真正不同的 IP。
///
/// 变异验证：把 `AgentKey` 的 `peer_ip` 从 `Hash`/`Eq` 里去掉（或固定成常量）⇒ 第二条注册会顶掉
/// 第一条，`/system/agents` 只剩一行，本用例红。
#[tokio::test]
#[serial]
async fn e2e_same_agent_id_from_two_source_ips_coexists() {
    // 双栈监听：[::] 这一个 socket 同时收 v4 与 v6（实测两种客户端都能握手）。
    let t = start_gateway(|o| {
        o.admin_token = Some("admin-token".into());
        o.quic_bind = "[::]:0".parse().unwrap();
    })
    .await;
    let port = t.quic_connect.port();

    // 同一个 agent_id，两个来源 IP（同一端口：双栈监听同时收 v4 与 v6）
    register_raw_agent_from(port, "127.0.0.1:0", &t.certs, "edge", 4).await;
    register_raw_agent_from(port, "[::1]:0", &t.certs, "edge", 4).await;
    wait_for_agents(&t.gw, 2, Duration::from_secs(10)).await;

    // `/system/agents` 必须给出**同名两行**，各自带自己的来源 IP
    let agents: serde_json::Value = test_client()
        .get(format!("{}/system/agents", t.base))
        .header("Authorization", "Bearer admin-token")
        .send()
        .await
        .expect("/system/agents 应当可查")
        .json()
        .await
        .expect("/system/agents 应当返回 JSON");
    let rows: Vec<(String, String)> = agents
        .as_array()
        .expect("应当是数组")
        .iter()
        .map(|e| {
            (
                e["agent_id"].as_str().unwrap_or_default().to_string(),
                e["ip"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            ("edge".to_string(), "127.0.0.1".to_string()),
            ("edge".to_string(), "::1".to_string()),
        ],
        "同名两个来源 IP 必须并存，且各自带着自己的 ip（按 (agent_id, ip) 稳定排序）"
    );
}
