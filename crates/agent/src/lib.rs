//! edge-agent：常驻 LLM 所在机器（edge 节点），主动拨 QUIC 长连接上云，把云端请求转发给本地 LLM。

pub mod tls;

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use proto::{
    io::{write_frame, FrameReader},
    Frame,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use s2n_quic::{client::Connect, provider::limits::Limits};
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use crate::stream::handle_stream;

pub mod config;
pub mod error;
pub mod stream;

pub struct AgentConfig {
    /// 云端网关 QUIC 地址。
    pub cloud_addr: SocketAddr,
    /// 证书校验用的服务器名（须与网关证书 SAN 匹配）。
    pub server_name: String,
    pub ca_cert: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub agent_id: String,
    pub models: Vec<String>,
    pub max_concurrency: u32,
    /// 本地 LLM 的 OpenAI 兼容地址，如 http://127.0.0.1:11434
    pub upstream_base: String,
    pub heartbeat_interval: Duration,
    /// 是否打印每请求的转发日志（received/responded/done/cancelled）。
    /// 高并发/压测时建议关闭，避免日志刷屏；连接/注册等低频日志不受此开关影响。
    pub request_log: bool,
}

/// `Agent` 的运行结局。
///
/// `run` 是无限重连循环，正常**永不结束**，所以"有结局"本身就是要上报的异常（`Cancelled`
/// 除外 —— 那是我们自己关的）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExit {
    /// run 循环返回了（不该发生）。
    LoopExited,
    /// run 循环 panic 了。
    Panicked,
    /// run 循环被取消 —— 即 `Agent::shutdown`。
    Cancelled,
}

impl AgentExit {
    /// 只有 `Cancelled` 是我们自己关的，不算"异常结局"（调用方不必以非 0 退出）。
    ///
    /// 单独抽出来是为了能直接单测这条映射：它挂在 `Agent::wait_for_abnormal_exit` 上，而那条
    /// 路径要"关掉之后还能问一次"，需要 `shutdown` 取 `&mut self`（会牵动 38 个 e2e 调用点），
    /// 为 3 行映射不值当（P3-5）。
    fn as_abnormal(self) -> Option<Self> {
        match self {
            Self::Cancelled => None,
            abnormal => Some(abnormal),
        }
    }
}

pub struct Agent {
    task: tokio::task::JoinHandle<()>,
    /// 守护任务给出的结局（`None` = 还没结束）。
    outcome: tokio::sync::watch::Receiver<Option<AgentExit>>,
}

impl Agent {
    pub fn start(cfg: AgentConfig) -> anyhow::Result<Self> {
        // provider 由 `tls::rustls_client_tls` 自己确保（幂等），这里不再需要显式安装。
        let client_config = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )?;
        Ok(Self::supervise(
            async move { run(cfg, client_config).await },
        ))
    }

    /// 守护一个"应当永不结束"的 run future，并把它的结局交给调用方。
    ///
    /// 外层包一层守护的理由不变：run 正常**永不返回**，一旦返回（panic / 被取消），进程就只是
    /// "看起来还在运行"——main 停在 `shutdown_signal()`，既不重连也不退出，日志里也什么都没有。
    /// 静默的僵尸进程比一次崩溃难查得多。
    ///
    /// **但"退出进程"不在这里做**（P3-5）：那是进程级策略，属于二进制（`main.rs`）。库自己
    /// `std::process::exit` 会让 agent crate 无法被嵌入，而且进程内构造 `Agent` 的测试在 run
    /// 循环崩溃时会被把**整个测试二进制**带走。现在结局走一个 watch 通道，
    /// 调用方用 [`Agent::wait_for_abnormal_exit`] 接住并按自己的策略处置。
    fn supervise<F>(run_loop: F) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, outcome) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(async move {
            let mut inner = AbortOnDrop(tokio::spawn(run_loop));
            let exit = match (&mut inner.0).await {
                Ok(()) => {
                    error!(
                        "agent run loop exited; the caller should exit so the supervisor restarts us"
                    );
                    AgentExit::LoopExited
                }
                Err(e) if e.is_panic() => {
                    error!(
                        "agent run loop panicked: {e}; the caller should exit so the supervisor restarts us"
                    );
                    AgentExit::Panicked
                }
                Err(e) => {
                    warn!("agent run loop cancelled: {e}");
                    AgentExit::Cancelled
                }
            };
            let _ = tx.send(Some(exit));
        });
        Self { task, outcome }
    }

    pub async fn shutdown(self) {
        self.task.abort();
    }

    /// 等这次运行**异常结束**。
    ///
    /// - `Some(LoopExited | Panicked)`：run 循环没了，进程"看起来还活着、什么都不做"。调用方
    ///   应当打日志并以**非 0** 退出，交给外部守护（`deploy/agent.service` 是
    ///   `Restart=always` / `RestartSec=3`）重新拉起。
    /// - `None`：是我们自己 `shutdown()` 关的（正常退出）。
    pub async fn wait_for_abnormal_exit(&mut self) -> Option<AgentExit> {
        loop {
            let seen = *self.outcome.borrow_and_update();
            if let Some(exit) = seen {
                return exit.as_abnormal();
            }
            if self.outcome.changed().await.is_err() {
                // 发送端消失且没给出结局（守护任务被 abort）⇒ 我们自己关的
                return None;
            }
        }
    }
}

/// 内层 run 任务的 Drop 兜底：外层被 abort（`Agent::shutdown`）时连带把它也 abort。
/// 没有这层，`shutdown()` 只会停掉包装任务，真正的连接循环会变成孤儿继续跑。
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 重连退避基准（第一次重连等这么久）。
const BACKOFF_BASE: Duration = Duration::from_millis(500);
/// 标称上限。DESIGN §6.1 原设计是"抖动 + 上限 60s"，这里刻意取 30s：网关滚动重启后
/// agent 回归更快；握手风暴的余地由 `connect_once` 里的 30s 握手限时给（那段注释解释了
/// 为什么不能更短）。
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// 会话活过这么久才算"健康"，断开时才把退避重置回基准。
///
/// 阈值存在的唯一理由是记录 P2-1 那个根因：`connect_once` 返回 `Ok(())` 有**两种**语义——
/// "健康跑了很久后断开" 与 "刚注册就被踢"（如同名 `agent_id` 互踢、网关注册后立刻关连接）。
/// 旧代码把两者都当成前者、退避一律重置回 500ms，于是每 ~500ms 互踢一次、永不收敛
/// （实测：3 秒内 5 次连接、6 个 `/v1/slow` 全 502，而两侧进程与 `/admin/agents` 都正常）。
/// 现在**只看会话活了多久**，与 Ok/Err 无关。
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);
/// 抖动幅度（百分比）：多台 agent 同时断线（网关重启）时不要把重连挤在同一毫秒。
const BACKOFF_JITTER_PERCENT: u64 = 20;

/// 下一轮的标称退避：会话活得够久才重置，否则翻倍（封顶 [`BACKOFF_MAX`]）。
fn next_backoff(current: Duration, session_alive: Duration) -> Duration {
    if session_alive >= BACKOFF_RESET_AFTER {
        BACKOFF_BASE
    } else {
        std::cmp::min(current.saturating_mul(2), BACKOFF_MAX)
    }
}

/// 给标称退避加 ±[`BACKOFF_JITTER_PERCENT`]% 抖动，并**仍然封顶** [`BACKOFF_MAX`]
/// （顶上因此是单边缩小：一撮 agent 落在 `[24s, 30s]` 而不是同一个 30s）。
///
/// `entropy` 由调用方给：生产用时钟纳秒，测试直接喂值——策略是纯函数，才钉得住。
fn jittered(backoff: Duration, entropy: u64) -> Duration {
    let span = BACKOFF_JITTER_PERCENT * 2;
    let percent = 100 - BACKOFF_JITTER_PERCENT + (entropy % (span + 1));
    let micros = backoff.as_micros() * u128::from(percent) / 100;
    std::cmp::min(Duration::from_micros(micros as u64), BACKOFF_MAX)
}

/// 抖动的熵：不引入 `rand` 依赖（只为一个 ±20% 的抖动不值当），用时钟纳秒 + 秒数混合。
fn jitter_entropy() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()) ^ d.as_secs())
        .unwrap_or(0)
}

async fn run(cfg: AgentConfig, client_config: rustls::ClientConfig) {
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
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
fn upstream_client() -> anyhow::Result<reqwest::Client> {
    // 上游客户端走 reqwest 的 rustls no-provider 变体：**构建前**必须有进程默认 provider，
    // 否则 panic "No provider set"（见 `proto::crypto` 的模块说明）。
    proto::crypto::provider();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
        .build()?)
}

/// 排队超过这个时长才算"闸门真的在起作用"（避免把准入与在途之间的瞬时竞态也记成排队）。
const SLOT_WAIT_LOG_AFTER: Duration = Duration::from_millis(100);
/// 持续过载时的日志节流间隔：这个项目的日志单日 652MB（`TODO.md` 已登记），不能每请求一行。
const SLOT_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 本机并发闸门（记录 P2-3）：`max_concurrency` 不只是"告诉网关"，**本机也执行它**。
///
/// 为什么需要（纵深防御）：正常路径上网关按它对注册表的登记卡住并发
/// （`try_acquire_excluding` 保证 `inflight < max_concurrency`），所以今天不出事。但只要
/// 网关那侧不守约——最现实的一条是 agent 配 `max_concurrency: 0`（网关侧 `0` 的语义是
/// **不限**）、其次是网关准入被改坏或被换成别的实现——本机就会把最多 **1000** 条并发流
/// （QUIC 流额度）全压进一台只按 4 个并发配置的本地 LLM：显存打满、首字节从 1–3s 崩到
/// 几十秒，而**两侧都不报错**，只是"变慢/超时"。
///
/// `max == 0` = **不限**（与网关侧语义一致）⇒ 不建闸门，此时唯一上限仍是 QUIC 流额度。
struct ConcurrencyGate {
    sem: Arc<Semaphore>,
    max: u32,
    /// 累计排队次数（只进日志，用来一行看出"防御持续生效了多久"）。
    queued: u64,
    /// 上次因排队打日志的时刻（节流用）。
    last_log: Option<Instant>,
}

impl ConcurrencyGate {
    /// `max == 0` = 不限 ⇒ `None`（没有闸门）。
    fn new(max: u32) -> Option<Self> {
        (max > 0).then(|| Self {
            sem: Arc::new(Semaphore::new(max as usize)),
            max,
            queued: 0,
            last_log: None,
        })
    }

    /// 取一个并发许可；满了就**排队等**。
    ///
    /// 为什么不在这里回 `Frame::Error`：网关的准入计数与"实际在途"之间有微小竞态，
    /// 瞬时超发一点点时排队就能救回来；回错误则变成**用户可见的假失败**（网关不会为这种
    /// 帧错误换 agent 重试）。等待的上界由网关自己给（`head_timeout` 到了它会给客户端 504，
    /// 而我们这边照旧把上游请求跑完/被 Cancel）。
    async fn acquire(&mut self) -> OwnedSemaphorePermit {
        let started = Instant::now();
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore 只在本结构里，且从不 close");
        if started.elapsed() >= SLOT_WAIT_LOG_AFTER {
            self.queued += 1;
            if self
                .last_log
                .is_none_or(|t| t.elapsed() >= SLOT_LOG_INTERVAL)
            {
                self.last_log = Some(Instant::now());
                warn!(
                    max_concurrency = self.max,
                    queued_total = self.queued,
                    wait_ms = started.elapsed().as_millis(),
                    "本机并发已达声明的 max_concurrency，请求在排队；网关侧的准入与实际在途不一致？"
                );
            }
        }
        permit
    }

    /// 供测试观察节流状态。
    #[cfg(test)]
    fn queued(&self) -> u64 {
        self.queued
    }
}

async fn connect_once(
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

async fn register(mut conn: s2n_quic::connection::Handle, cfg: &AgentConfig) -> anyhow::Result<()> {
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

/// 取闸门许可的结果（复扫 E1）。
enum SlotOutcome {
    /// 拿到许可；`None` = 没开闸门（`max_concurrency = 0` = 不限）。
    Permit(Option<OwnedSemaphorePermit>),
    /// 等许可期间心跳结束了 —— 必须结束这条连接，交回 `run()` 重连。
    HeartbeatDown,
}

/// 取一个闸门许可，但**同时**盯着心跳（复扫 E1）。
///
/// 为什么必须放在 `select!` 里：`tokio::select!` 的分支体一旦 await，其它分支就不再被 poll。
/// 所以"在 accept 分支体里直接 `g.acquire().await`"会让**排队期间**心跳失败/panic 无人观察
/// ——连接不会被拆，agent 自认连着而网关全程 503（`run_connection` 顶部那段注释描述的静默态）。
///
/// 抽成独立函数是为了能直接测这条性质（见本文件测试里的
/// `waiting_for_a_slot_still_notices_a_dead_heartbeat`）：给一个许可已占满的闸门 + 一个已经
/// 结束的心跳，它必须**立刻**回 [`SlotOutcome::HeartbeatDown`]，而不是一直排队。
async fn acquire_slot(
    gate: &mut Option<ConcurrencyGate>,
    hb: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> SlotOutcome {
    let Some(g) = gate.as_mut() else {
        return SlotOutcome::Permit(None);
    };
    tokio::select! {
        r = &mut *hb => {
            report_heartbeat_down(r);
            SlotOutcome::HeartbeatDown
        }
        permit = g.acquire() => SlotOutcome::Permit(Some(permit)),
    }
}

/// 心跳任务结束时的统一处置（复扫 E1 把它从 `select!` 分支体里提出来）。
///
/// 提取的原因：下面 accept 循环里**有两处**要观察心跳——循环顶部，以及"等闸门许可"的那段。
/// 两处必须给出同一句日志，否则"哪种死法说什么话"就会随调用点漂移。
fn report_heartbeat_down(joined: Result<anyhow::Result<()>, tokio::task::JoinError>) {
    match joined {
        Ok(Ok(())) => warn!("heartbeat loop exited; forcing reconnect"),
        Ok(Err(e)) => warn!("heartbeat loop failed: {e}; forcing reconnect"),
        Err(e) if e.is_panic() => {
            error!("heartbeat loop panicked: {e}; forcing reconnect")
        }
        Err(e) => warn!("heartbeat task cancelled: {e}; forcing reconnect"),
    }
}

async fn heartbeat_loop(
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
async fn heartbeat_once(
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

#[cfg(test)]
pub(crate) mod test_log;

#[cfg(test)]
mod tests;
