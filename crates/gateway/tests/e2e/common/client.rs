//! e2e 的步骤窗口与有界 HTTP client。

use super::*;

/// 单个 e2e 步骤的墙钟上限（见 [`bounded`]）。
///
/// **取值 30s 是被两边夹出来的**：下界要高于网关自己在测试基线下的所有合法上限
/// （`head_timeout` 5s + 转发空闲 `request_timeout` 10s，关闭路径最坏
/// `shutdown_grace` 15s + `shutdown_flush_timeout` 10s + 收尾窗口 1s ≈ 26s）；
/// 上界要低于 `.config/nextest.toml` 的 `slow-timeout` 周期（60s），否则失败会被
/// nextest 先报成 TIMEOUT，丢掉步骤名这一关键信息。
///
/// 为什么需要它：e2e 里绝大多数 await **没有**任何超时（PROJECT_SCAN P2-17）。网关侧
/// 每一步虽然都有界，但"客户端一步卡住"在两种 runner 下的表现完全不同——
/// nextest 会在 180s 后杀掉进程、只留一句 TIMEOUT；`cargo test`（`make test`）下
/// 整条 e2e 是 `#[serial]` 的，一处卡住 = 套件无限期挂起。有了它，卡住会变成一条
/// **带步骤名**的失败。
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// 等 `fut` 完成，最多 [`STEP_TIMEOUT`]；超时则 panic 并点出是哪一步。
pub async fn bounded<F: std::future::Future>(step: &str, fut: F) -> F::Output {
    bounded_within(STEP_TIMEOUT, step, fut).await
}

/// 同 [`bounded`]，窗口可指定（守卫自身的哨兵测试要毫秒级窗口，见文件末尾的测试模块）。
pub async fn bounded_within<F: std::future::Future>(
    limit: Duration,
    step: &str,
    fut: F,
) -> F::Output {
    match tokio::time::timeout(limit, fut).await {
        Ok(v) => v,
        Err(_) => panic!(
            "e2e step {step:?} did not finish within {limit:?}; \
             the gateway or the mock upstream stalled at this step"
        ),
    }
}

/// 测试用 reqwest client：**整条请求（含读响应体）的总超时**为 [`STEP_TIMEOUT`]。
///
/// "这一步本该完成"的用例一律用它——一个裸 `Client::new()` 会一直等下去（见哨兵
/// `a_bare_client_waits_forever_while_a_bounded_one_gives_up`），而 e2e 是 `#[serial]`：
/// 一处卡住 = `cargo test` 下整个套件无限期挂起、nextest 下只有一句 TIMEOUT。
///
/// **三类必须继续用裸 client**（它们要的就是"卡住"）：
/// - `stalls.rs`（请求体/响应体停滞）、`write_backpressure.rs`（写背压）：
///   断言的前提就是客户端不被服务；
/// - `https.rs::e2e_proxy_protocol_edge_cases`：好几个断言期待"body 读到一半出错"，
///   加了总超时会让它们变成"超时才出错"，断言虽仍通过但验的不是同一件事。
pub fn test_client() -> reqwest::Client {
    test_client_within(STEP_TIMEOUT)
}

/// 同 [`test_client`]，窗口可指定（哨兵测试要毫秒级窗口）。
pub fn test_client_within(limit: Duration) -> reqwest::Client {
    // 同上：reqwest 的 no-provider 变体要求进程默认 provider 已在，否则构建即 panic。
    proto::crypto::provider();
    reqwest::Client::builder()
        .timeout(limit)
        .build()
        .expect("reqwest client")
}
