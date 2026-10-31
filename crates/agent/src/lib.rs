//! edge-agent：常驻 LLM 所在机器（edge 节点），主动拨 QUIC 长连接上云，把云端请求转发给本地 LLM。
//!
//! 模块分工：`session` 管一条连接的生命周期（拨号/注册/心跳/收流），`gate` 管本机并发闸门
//! 与心跳观察，`backoff` 管重连退避/抖动；本文件只留 [`Agent`] 句柄与退出语义。

pub mod tls;

use std::{net::SocketAddr, time::Duration};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{error, warn};

mod backoff;
pub mod config;
pub mod error;
mod gate;
mod session;
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
    /// 所属 tenant；`None` 表示 legacy `Register`（仅迁移期允许）。
    pub tenant_id: Option<String>,
    /// tenant agent token；绝不能进日志。
    pub tenant_agent_token: Option<String>,
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
    pub fn start(cfg: AgentConfig) -> Result<Self, error::AgentError> {
        // provider 由 `tls::rustls_client_tls` 自己确保（幂等），这里不再需要显式安装。
        let client_config = tls::rustls_client_tls(
            &cfg.ca_cert,
            cfg.client_cert.clone(),
            cfg.client_key.clone_key(),
        )?;
        Ok(Self::supervise(async move {
            session::run(cfg, client_config).await
        }))
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

#[cfg(test)]
pub(crate) mod test_log;

#[cfg(test)]
mod tests;
