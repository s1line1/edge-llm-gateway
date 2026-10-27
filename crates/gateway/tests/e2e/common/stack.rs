//! e2e 的网关/全栈启动夹具。

use super::*;

/// 裸网关 + 它周围的材料：证书、已种好的 api key、keys.db 路径、http base。
///
/// 多 agent / 异构模型 / 裸 QUIC 客户端 / 自定义上游这类要自己控制"网关之外那一半"的场景
/// 用它；只要一套标准栈（mock-llm + 一个 test-agent）就用 [`start_stack`]。
pub struct TestGateway {
    pub gw: Gateway,
    pub certs: TestCerts,
    pub key: String,
    /// 已种好的 keys.db 路径（少数用例要自己对它拿独占锁）。
    pub keys_path: PathBuf,
    /// `http://<真实端口>`。
    pub base: String,
    /// 可直连的 QUIC 地址。
    ///
    /// 为什么与 `gw.quic_addr` 分开：`quic_bind` 配成通配地址（`0.0.0.0:0` 或 `[::]:0`）时，
    /// `local_addr()` 报回来的是**未指定地址**加真实端口——客户端无法把 `0.0.0.0` 当目的地。
    /// 这个字段把通配折成回环（v4 → `127.0.0.1`，v6 → `::1`，两者共用同一个端口与同一个 socket）。
    pub quic_connect: SocketAddr,
}

/// 把"未指定地址"折成可直连的回环地址（见 [`TestGateway::quic_connect`]）。
pub fn connectable(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, addr.port())
}

/// 起一个**裸网关**（不接 agent）。`tune` 只改这个用例真正要动的旋钮。
///
/// 测试基线刻意与库默认（生产数值）不同：超时压到秒级——否则一条注定失败的用例会静默多挂
/// 十几秒（`request_timeout` 库默认 120s）。端口用库默认的 `127.0.0.1:0`（内核分配，靠
/// `gw.http_addr` 回读），UI 目录不配。
pub async fn start_gateway(tune: impl FnOnce(&mut Options)) -> TestGateway {
    start_gateway_with(move |o, _certs| tune(o)).await
}

/// e2e 的旋钮基线（与库默认不同：超时压到秒级，否则一条注定失败的用例要挂十几秒）。
pub fn e2e_options(keys_file: Option<PathBuf>) -> Options {
    Options {
        keys_file,
        request_timeout: Duration::from_secs(10),
        tunnel_op_timeout: Duration::from_secs(2),
        head_timeout: Duration::from_secs(5),
        agent_stale_after: Duration::from_secs(10),
        client_stall: Duration::from_secs(60),
        allow_legacy_agent_registration: true,
        ..Options::default()
    }
}

/// 用给定旋钮组装一份 [`GatewayConfig`]（不启动）——要断言"启动**之前**就失败"的用例需要它。
pub fn gateway_config(certs: &TestCerts, opts: Options) -> GatewayConfig {
    GatewayConfig {
        tunnel: certs.tunnel_tls(),
        opts,
    }
}

/// 同 [`start_gateway`]，但 `tune` 还能拿到证书材料——HTTPS 入口的 PEM 只有生成之后才知道。
pub async fn start_gateway_with(tune: impl FnOnce(&mut Options, &TestCerts)) -> TestGateway {
    let certs = TestCerts::generate();

    let (keys_path, key) = seed_keys_db();
    let mut opts = e2e_options(Some(keys_path.clone()));
    tune(&mut opts, &certs);

    let gw = Gateway::start(gateway_config(&certs, opts)).await.unwrap();

    let base = format!("http://{}", gw.http_addr);
    TestGateway {
        quic_connect: connectable(gw.quic_addr),
        gw,
        certs,
        key,
        keys_path,
        base,
    }
}

/// 拉起一整套栈（mock-llm + gateway + 一个 test-agent），返回 (gw, agent, http base, api key)。
///
/// `max_concurrency` 是 **agent 侧**的并发上限（准入控制的依据）；网关旋钮一律通过
/// `tune` 闭包表达。以前这里有 6 个近邻函数（`start_stack_with_verify_cache` /
/// `_with_tunnel_timeout` / `_full` / `_with_admission` / `_with_head_timeout` /
/// `start_stack` 自身），每加一种测试变体就得再写一个；现在变体是闭包，**不会再长**。
pub async fn start_stack(
    max_concurrency: u32,
    tune: impl FnOnce(&mut Options),
) -> (Gateway, Agent, String, String) {
    let (gw, agent, base, key, _mock_addr) = start_stack_with_mock(max_concurrency, tune).await;
    (gw, agent, base, key)
}

/// 同 [`start_stack`]，但把 mock-llm 的地址也交出来——要断言**上游侧**行为（例如
/// `/stats` 里"被中途取消的响应体数"）的用例需要直接访问上游。
pub async fn start_stack_with_mock(
    max_concurrency: u32,
    tune: impl FnOnce(&mut Options),
) -> (Gateway, Agent, String, String, SocketAddr) {
    let t = start_gateway(tune).await;
    let mock_addr = start_mock_llm("mock-llm").await;
    let agent = t.certs.agent(
        &t.gw,
        "test-agent",
        &["mock-llm"],
        mock_addr,
        max_concurrency,
        true,
    );
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;
    let TestGateway { gw, key, base, .. } = t;
    (gw, agent, base, key, mock_addr)
}
