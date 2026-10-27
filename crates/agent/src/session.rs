//! 一条 QUIC 连接的生命周期：拨号 → 注册 → 心跳 → 收流 → 转发。
//!
//! 这里放"连接活着时会发生什么"；退出/重连策略在 [`crate::backoff`]，本机闸门在
//! [`crate::gate`]，进程级句柄与退出语义在 `lib.rs`。

use std::{sync::Arc, time::Duration};

use proto::{
    io::{write_frame, FrameReader},
    Frame,
};
use s2n_quic::{client::Connect, provider::limits::Limits};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::{
    backoff::{jitter_entropy, jittered, next_backoff, BACKOFF_BASE},
    gate::{acquire_slot, report_heartbeat_down, ConcurrencyGate, SlotOutcome},
    stream::handle_stream,
    AgentConfig,
};

pub(crate) async fn run(cfg: AgentConfig, client_config: rustls::ClientConfig) {
    let mut backoff = BACKOFF_BASE;
    loop {
        let started = std::time::Instant::now();
        let outcome = connect_once(&cfg, client_config.clone()).await;
        let session_alive = started.elapsed();
        // 先算出真正要等多久再打日志：日志里的值必须就是实际睡的值（排查时据此对齐
        // 两侧时间线），而且抖动过的值才看得出"多台机器错开了"。
        let wait = jittered(backoff, jitter_entropy());
        match outcome {
            Ok(()) => info!(
                session_alive_secs = session_alive.as_secs(),
                wait_ms = wait.as_millis(),
                "disconnected from cloud, reconnecting"
            ),
            Err(e) => warn!(
                session_alive_secs = session_alive.as_secs(),
                wait_ms = wait.as_millis(),
                "agent error: {e}; retrying"
            ),
        }
        tokio::time::sleep(wait).await;
        backoff = next_backoff(backoff, session_alive);
    }
}

/// 连上游时的"连上"超时。**不是**总超时——总超时会腰斩合法的长 SSE 流（记录 R10 的坑）。
pub(crate) const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// 上游 HTTP 客户端。三个默认值必须显式改掉（记录 P2-4）：
///
/// - **不跟随重定向**：`reqwest` 默认跟随最多 10 跳，而上游就是本地固定端点，重定向没有任何
///   正当用途。跟随的后果不只是"多跳一次"：307/308 会把**方法连同 prompt 一起重发**到
///   `Location` 指定的地址（内网服务、云元数据 `169.254.169.254`），并把那边的**响应**
///   回给调用方——等于把一次 SSRF 和一条数据出境路径交给本地 LLM、或交给能改写它响应的人。
/// - **不读环境代理**：edge 机器上存在 `HTTP_PROXY`/`ALL_PROXY` 时，prompt 会静默经该代理。
///   今天 `Cargo.toml` 里 `reqwest` 关了默认特性、`system-proxy` 未启用，所以**已经**不读；
///   显式写出来是为了别人日后打开默认特性时不悄悄多一条出境路径。⚠️ 这一条**没有**行为测试
///   钉着（特性没开时它无从观测），属"显式声明"而非"已验证"。
/// - **连接有超时**：上游不监听时不要无限等。响应阶段的兜底在网关侧（`head_timeout` 与
///   逐帧空闲超时 → 发 `Cancel`），所以这里只限"连上"这一跳，不设总超时。
pub(crate) fn upstream_client() -> anyhow::Result<reqwest::Client> {
    // 上游客户端走 reqwest 的 rustls no-provider 变体：**构建前**必须有进程默认 provider，
    // 否则 panic "No provider set"（见 `proto::crypto` 的模块说明）。
    proto::crypto::provider();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
        .build()?)
}

pub(crate) async fn connect_once(
    cfg: &AgentConfig,
    client_config: rustls::ClientConfig,
) -> anyhow::Result<()> {
    // let limits = Limits::new().with_max_idle_timeout(Duration::from_secs(20))?; // 对齐 quinn 时代的 20s
    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(20))?
        .with_max_open_remote_bidirectional_streams(1000)?
        // s2n-quic 默认握手限时 10s（`MAX_HANDSHAKE_DURATION_DEFAULT`）。实测在网关
        // 高并发（数百条流在途）时新连接握不上手，日志是
        // `MaxHandshakeDurationExceeded { max_handshake_duration: 10s }`，
        // 于是"心跳超时→断开→重连→握手又超时"形成风暴。放到 30s 给拥塞留余地；
        // 真正的重连退避由 `run()` 的指数退避负责（上限 30s）。
        .with_max_handshake_duration(Duration::from_secs(30))?;

    // 不设 with_max_idle_timeout 时默认 30s（MaxIdleTimeout::RECOMMENDED）
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            client_config,
        )))?
        .with_io("0.0.0.0:0")?
        .with_limits(limits)?
        .start()?;
    let mut conn = client
        .connect(Connect::new(cfg.cloud_addr).with_server_name(cfg.server_name.clone()))
        .await?;

    // 保活：s2n-quic 的周期 = min(本端 max_idle_timeout × 3/4, max_keep_alive_period)
    // —— 这里是 min(20s × 3/4, 30s) = 15s。它小于协商出的空闲超时
    //    （min(本端 20s, 网关 30s) = 20s），网关才不会把连接判空闲关掉。
    //    公式见 s2n-quic-transport 的 `KeepAlive::new`（用的是本端 limits，不是协商值）；
    //    `max_keep_alive_period` 默认 30s。
    conn.keep_alive(true)?;

    // ① 先拆：Handle 用来"开流"（Register/Heartbeat），acceptor 用来"收流"（代理请求）
    let (handle, mut acceptor) = conn.split();

    info!("connected to cloud gateway at {}", cfg.cloud_addr);

    // ② Register 用 handle 开一条流发注册帧
    register(handle.clone(), cfg).await?;

    info!(agent_id = %cfg.agent_id, models = ?cfg.models,max_concurrenty = cfg.max_concurrency,"registered with cloud gateway");

    // ③ 心跳任务拿到 handle 的 clone（各任务一份，互不冲突）
    let mut hb = tokio::spawn(heartbeat_loop(
        handle.clone(),
        cfg.agent_id.clone(),
        cfg.heartbeat_interval,
    ));

    let http = upstream_client()?;
    // ④ accept 循环用 acceptor（单消费者，独占）
    //
    // 和心跳**并跑**，而不是各跑各的：心跳是网关判定"这个 agent 还活着"的唯一依据
    // （网关侧 stale 判定默认 15s，agent 侧心跳默认 5s 一次）。心跳任务一旦结束，
    // 哪怕 QUIC 连接本身还开着，这条连接在网关眼里也已经死了 —— 表现是"agent 自认为
    // 连着、网关把所有请求判 503、两侧都没有日志、只能人工重启"的静默态。
    // 所以必须观察它：它一结束就结束这条连接，交回 run() 的重连循环。
    // 本机并发闸门（记录 P2-3）：`max_concurrency > 0` 时才有闸门，"0 = 不限"与网关侧同理。
    let mut gate = ConcurrencyGate::new(cfg.max_concurrency);
    loop {
        tokio::select! {
            r = &mut hb => {
                report_heartbeat_down(r);
                break;
            }
            accepted = acceptor.accept_bidirectional_stream() => match accepted {
                Ok(Some(stream)) => {
                    // 先拿许可**再**接手：闸门满了就停在这里不再 accept 下一条流——未接收的流
                    // 留在 QUIC 层，流控自然形成背压，最终由网关自己的 `head_timeout` 收尾
                    // （客户端看到 504）。许可随任务存活，本请求跑完才释放。
                    //
                    // 取许可走 `acquire_slot`：它把心跳也放进同一个 `select!`，所以**排队期间**
                    // 心跳结束仍会被观察到（复扫 E1，见该函数的说明）。
                    let permit = match acquire_slot(&mut gate, &mut hb).await {
                        SlotOutcome::Permit(p) => p,
                        SlotOutcome::HeartbeatDown => break,
                    };
                    let http = http.clone();
                    let upstream_base = cfg.upstream_base.clone();
                    let request_log = cfg.request_log;
                    tokio::spawn(async move {
                        let _permit = permit;
                        // 记录 P2-2：以前这里是 `let _ = ...`，`handle_stream` 的所有失败
                        // （上游连不上、首帧不是 ProxyRequest、写帧失败…）连一行日志都没有。
                        // `{e:#}` 打印整条 context 链（带 request_id / path）。
                        if let Err(e) = handle_stream(stream, http, upstream_base, request_log).await {
                            warn!("proxy stream failed: {e:#}");
                        }
                    });
                }
                Ok(None) => break, // 连接正常关闭
                Err(e) => {
                    warn!("accept stream failed: {e}");
                    break;
                }
            },
        }
    }

    hb.abort();
    Ok(())
}

pub(crate) async fn register(
    mut conn: s2n_quic::connection::Handle,
    cfg: &AgentConfig,
) -> anyhow::Result<()> {
    // open a new stream and split the receiving and sending sides
    let stream = conn.open_bidirectional_stream().await?;
    let client_id = stream.id();
    // 曾经是 println!：没有时间戳、没有级别，混在日志里像噪声，措辞也不对
    // （注册的是 agent，不是 server）。
    debug!(client_id, "registering with cloud gateway");

    let (recv, mut send) = stream.split();

    write_frame(
        &mut send,
        &Frame::Register {
            agent_id: cfg.agent_id.clone(),
            models: cfg.models.clone(),
            max_concurrency: cfg.max_concurrency,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )
    .await?;
    send.finish()?;
    // // 网关不发 ack；读到 EOF 即可
    let mut reader = FrameReader::new(recv);
    tokio::time::timeout(Duration::from_secs(10), reader.next())
        .await
        .map_err(|_| anyhow::anyhow!("register timed out waiting for gateway EOF"))? // 超时
        .map_err(|e| anyhow::anyhow!("register read failed: {e}"))?; // io::Error

    Ok(())
}

pub(crate) async fn heartbeat_loop(
    mut conn: s2n_quic::connection::Handle,
    agent_id: String,
    interval: Duration,
) -> anyhow::Result<()> {
    // 单次心跳的等待上限：**与心跳间隔解耦**。原来是硬编码 5s，恰好等于默认的
    // 5s 心跳间隔、零余量；而满负载时 `open_bidirectional_stream()` 要抢连接级流
    // 管理器，稍一排队就超时——一次超时就把整条连接拆掉，代价是此后十几秒内网关
    // 没有任何健康 agent（所有请求 503）。取 3× 间隔（默认 15s）留出排队余量。
    let wait = interval.saturating_mul(3);
    // 允许连续失败次数：一次超时不代表连接坏了，但也不能无限忍——否则网关早已按
    // stale 判死（默认 15s），agent 还抱着连接不动。
    //
    // 取 2 的算式（默认 interval=5s、wait=15s）：容忍窗口 ≈
    // `2 × interval + wait` = 10 + 15 = 25s，略大于网关的 stale 窗口 15s，
    // 即"还在容忍"期间网关最多已经判了 10s 的 stale —— 再长就等于装死。
    const MAX_CONSECUTIVE_FAILURES: u32 = 2;
    let mut failures = 0u32;
    loop {
        tokio::time::sleep(interval).await;
        match heartbeat_once(&mut conn, &agent_id, wait).await {
            Ok(()) => failures = 0,
            Err(e) => {
                failures += 1;
                warn!(
                    failures,
                    max = MAX_CONSECUTIVE_FAILURES,
                    "heartbeat failed: {e}; will keep the connection until failures accumulate"
                );
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    return Err(anyhow::anyhow!(
                        "heartbeat failed {failures} times in a row: {e}"
                    ));
                }
            }
        }
    }
}

/// 发一次心跳并等网关回包；整体（开流 + 写帧 + 收帧）受 `wait` 约束。
pub(crate) async fn heartbeat_once(
    conn: &mut s2n_quic::connection::Handle,
    agent_id: &str,
    wait: Duration,
) -> anyhow::Result<()> {
    let exchange = async {
        // 心跳走一条独立短流（开→写→半关→读完），不与业务流共用编码状态
        let stream = conn.open_bidirectional_stream().await?;
        let (recv, mut send) = stream.split();
        write_frame(
            &mut send,
            &Frame::Heartbeat {
                agent_id: agent_id.to_string(),
                inflight: 0,
            },
        )
        .await?;
        send.shutdown().await?;
        let mut reader = FrameReader::new(recv);
        while reader.next().await?.is_some() {}
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(wait, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("heartbeat timed out after {wait:?}"))?
}
