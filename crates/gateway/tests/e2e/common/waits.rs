//! e2e 的 mock 上游、注册/在途等待与 `/metrics` 读取。

use super::*;

pub async fn start_mock_llm(name: &str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let name = name.to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_llm::router(&name)).await;
    });
    addr
}

pub async fn wait_for_agents(gw: &Gateway, count: usize, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if gw.agent_count() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("expected {count} agents, got {}", gw.agent_count());
}

/// 等注册表里**恰好剩下** `want` 个 agent；超时 panic，`what` 写进文案说明在等什么。
///
/// 为什么不复用 [`wait_for_agents`]：那条判据是"**至少** N 个"（启动期等待），所以
/// `wait_for_agents(gw, 0, ..)` 会**立刻**返回——等不了"降到 0"。
///
/// 为什么需要它（复扫 F3）：摘除是**异步**的——连接断开要经 QUIC 传播到网关的 accept 循环，
/// 再摘掉条目，中间没有同步点。固定的 `sleep(300ms)` 是在睡猜这个窗口：机器快时白等，机器慢
/// 或 CI 负载高时就是假失败。这里改成"有界轮询到事实发生"，超时才报错并把实际值带出来。
pub async fn wait_for_agent_count(gw: &Gateway, want: usize, what: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if gw.agent_count() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "{what}: expected exactly {want} agent(s) within {timeout:?}, still {}",
        gw.agent_count()
    );
}

/// 建一个临时 SQLite 库并种入一个测试 key，返回 (库路径, key)。
/// 临时目录被 forget 保活，避免网关持有连接时库文件被清理。
pub fn seed_keys_db() -> (PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = gateway::storage::Storage::new(Some(path.clone()));
    let created = store.create("e2e".into()).unwrap();
    std::mem::forget(dir);
    (path, created.plaintext)
}

/// 读 `/metrics` 里的某个 gauge 值（测试用它断言"槽位是否归还"）。
/// 等"至少一个 agent 的在途数 ≥ `want`"（读 `/admin/agents` 的实时视图；需要测试里配
/// `admin_token = Some("admin-token")`）。
///
/// 为什么需要它（记录 P2-18）：并发 e2e 的断言——"恰好一个 200 + 一个 429"、"两个请求分散到
/// 两台 agent"——只有在**两次请求真的重叠**时才成立。靠上游 `sleep` 的时长窗口去赌重叠是时序
/// 赌博（调度一慢就串行化 ⇒ 两个都 200 ⇒ 断言失败）。这里改成"**等槽位真的被占上**，再发第二个
/// 请求"，把重叠用事实构造出来。
pub async fn wait_for_any_agent_inflight(base: &str, want: u64) {
    let client = test_client();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        // 解析失败按"还没就绪"处理、继续轮询——**不要 panic**：这个函数本身就是个轮询循环，
        // 而 `/admin/agents` 在网关刚起来/连接刚建立的那个瞬间可能返回一个 `.json()` 解析不了的
        // 体（实测：`EOF while parsing a value, line 1 column 0`）。以前这里 `.unwrap()` 会把这个
        // **瞬态**变成整条用例的硬失败，只因为它恰好落在第一次轮询上（`agents.rs` 的既有用法
        // 触发不到，新加的接管用例会）。
        let agents: serde_json::Value = match client
            .get(format!("{base}/admin/agents"))
            .header("Authorization", "Bearer admin-token")
            .send()
            .await
        {
            Ok(resp) => match resp.json().await {
                Ok(v) => v,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            },
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let total: u64 = agents
            .as_array()
            .map(|list| list.iter().filter_map(|e| e["inflight"].as_u64()).sum())
            .unwrap_or(0);
        if total >= want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "等 agent 在途数 ≥{want} 超时；/admin/agents = {agents}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub async fn metric_gauge(base: &str, name: &str) -> u64 {
    // 用有界客户端（重扫 F2）：`reqwest::get` 内部是**默认无超时**的 client，而本函数被
    // `head_timeout`/`write_backpressure`/`stalls` 多条 e2e 当作"读一个指标"的一步调用 ——
    // `/metrics` 一旦卡住，`cargo test` 下整套会无限期挂起。
    let text = test_client()
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    text.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == name).then(|| v.trim().parse().ok())?
        })
        .unwrap_or_else(|| panic!("指标 {name} 不在 /metrics 输出里"))
}
