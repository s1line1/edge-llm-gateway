//! 关闭阶段的唯一所有者：推进规则、等待窗口与"发送端消失"信号。
//!
//! 为什么单独成模块（并集评估 §2 S3 / 核心评估 C1）：关闭阶段的**能力**与**规则**原先
//! 散在 `state.rs`（`Option<watch::Sender>` + `take()` + `expect`）与 `gateway.rs`
//! （`shutdown` 里的两次 `send`、`drain`、`await_end_event_window`）三处。单发送端这条
//! 不变量只靠一段 20 行注释和一条测试保护，任何一次 `AppState::clone` 里顺手 `clone()`
//! 一次发送端都会让它静默失效。
//!
//! 现在：`Controller` 是**唯一**持有 `watch::Sender` 的类型，只给 `pub(crate)` 的
//! `begin_drain` / `terminate`；推进只允许 `Running → Draining → Terminating`。`AppState`
//! 只拿接收端（查询/订阅），所以 `AppState` 的克隆**在类型上**不可能把通道钉活。
//! 通道关闭（`Controller` 被 drop，即 `Gateway` 没了）仍是各连接任务的硬停信号，见
//! [`wait_closed`]。

use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

use crate::metrics::Metrics;

/// 关闭阶段。`Running` → `Draining` → `Terminating`，只向一个方向走。
///
/// 三类消费者：
/// - **accept 循环**（`http/entry.rs`）：`Draining` 起停止接受新连接，但在途请求继续跑；
/// - **每条在途响应**（`proxy/forward.rs`）：`Terminating` 起带一个明确的"不完整"事件收尾，
///   而不是被硬切；
/// - **每连接任务**：只关心**发送端消失**（= `Gateway` 被 drop），见 [`wait_closed`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownPhase {
    Running,
    Draining,
    Terminating,
}

/// 宣布 `Terminating` 后留给在途响应把"不完整"事件写出去的窗口。
///
/// 刻意不做成新旋钮：它只是"把事件从网关写到客户端"的调度余量，通常一两个调度周期就够；
/// 给固定上限是为了不让一个不读的客户端拖住关闭。
const END_EVENT_WINDOW: Duration = Duration::from_secs(1);

/// 关闭阶段的控制器：**唯一**持有发送端，并且只允许单向推进。
///
/// 由 `Gateway` 独占；`AppState` 只经 [`Controller::subscribe`] 拿接收端。
pub(crate) struct Controller {
    tx: watch::Sender<ShutdownPhase>,
}

impl Controller {
    pub(crate) fn new() -> Self {
        let (tx, _rx) = watch::channel(ShutdownPhase::Running);
        Self { tx }
    }

    /// 当前阶段（只读）。
    pub(crate) fn phase(&self) -> ShutdownPhase {
        *self.tx.borrow()
    }

    /// 订阅后续阶段变化：每个 accept 循环/在途响应各持一个接收端。
    pub(crate) fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.tx.subscribe()
    }

    /// 进入 `Draining`：公网入口停止 accept，在途请求继续跑。
    pub(crate) fn begin_drain(&self) {
        self.advance(ShutdownPhase::Draining);
    }

    /// 进入 `Terminating`：在途响应带一个明确的"不完整"事件收尾。
    pub(crate) fn terminate(&self) {
        self.advance(ShutdownPhase::Terminating);
    }

    /// 单调推进：同一阶段/回退都不发通知（避免重复唤醒与阶段倒退）。
    fn advance(&self, next: ShutdownPhase) {
        if next > self.phase() {
            // `send` 在没有接收端时会失败（且不更新值）；`send_replace` 总是写入，
            // 然后通知当前订阅者。关闭阶段是进程状态，不能因为"此刻没人订阅"而丢。
            let _ = self.tx.send_replace(next);
        }
    }

    /// 等在途 HTTP 请求归零，或到 `grace`。
    ///
    /// 判据用 [`Metrics::active_count`]（与 `hlmg_active_requests` 同一份计数）：它覆盖
    /// "准入之后、响应体结束之前"的整段；响应体结束意味着隧道与用量结算都已收口。
    pub(crate) async fn drain(&self, metrics: &Metrics, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let active = metrics.active_count();
            if active == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    active,
                    grace_secs = grace.as_secs(),
                    "shutdown grace elapsed with requests still in flight; announcing termination"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// 宣布 `Terminating` 之后，等在途响应把明确事件写出去：在途归零或到 [`END_EVENT_WINDOW`]。
    ///
    /// **窗口到点仍有在途要说出来**：这个读数（`hlmg_active_requests`）由**响应 body** 持有，
    /// 而 body 归 HTTP 连接任务；客户端停止读取时它会 park 在写 socket 上，直到 `client_stall`
    /// （见 `io_stall::WriteStall`）——此时**转发任务早已收尾**（它在 `Terminating` 就被叫停并
    /// 把 Cancel 发给了上游），在途读数却仍 >0。所以这条 WARN 说的是"有客户端不读，票据要等
    /// 停滞上限才归还"，不是"任务泄漏"；要区分得看
    /// `hlmg_client_stalls_total{phase="response-body"}`。
    pub(crate) async fn await_end_event_window(&self, metrics: &Metrics) {
        let deadline = tokio::time::Instant::now() + END_EVENT_WINDOW;
        loop {
            let active = metrics.active_count();
            if active == 0 {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    active,
                    window_ms = END_EVENT_WINDOW.as_millis(),
                    "still in flight when the end-event window elapsed: the forward tasks have been \
                     told to stop, but these admission tickets are held by HTTP connection tasks \
                     whose client stopped reading; they are released at client_stall at the latest"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// 等到关闭通道**关闭**：也就是持有唯一 [`Controller`] 的 `Gateway` 被 drop。
///
/// 与 [`ShutdownPhase`] 的推进**不是一回事**，两个方向都不能混：
/// - `Draining` 只停 accept，已建立的连接要继续服务在途请求；
/// - `Terminating` 之后还有 [`END_EVENT_WINDOW`] 让在途响应把"不完整"事件真的写出去。
///
/// 只有"发送端没了"才意味着网关对象已经不在了、连接没有继续存在的理由（`Gateway` 的 `Drop`
/// 承诺 abort 所有任务，而它只能 abort 那三个主任务句柄）。`watch::Receiver::changed()` 在
/// 阶段变化时返回 `Ok`、在**所有发送端消失**后返回 `Err`，所以这个循环只在后者退出。
pub(crate) async fn wait_closed(rx: &mut watch::Receiver<ShutdownPhase>) {
    while rx.changed().await.is_ok() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格：阶段只向一个方向走。`Terminating` 之后的 `begin_drain` 是 no-op（不能回退），
    /// 且同一阶段重复推进不产生新通知。
    #[test]
    fn phases_only_move_forward() {
        let controller = Controller::new();
        assert_eq!(controller.phase(), ShutdownPhase::Running);

        controller.terminate();
        assert_eq!(controller.phase(), ShutdownPhase::Terminating);

        controller.begin_drain();
        assert_eq!(
            controller.phase(),
            ShutdownPhase::Terminating,
            "Draining 不得把已 Terminating 的阶段打回去"
        );
    }

    /// 规格（复扫 D5）：**`AppState` 及其克隆不得把关闭通道钉活**。
    ///
    /// 通道在最后一个发送端消失时才算"关闭"，而在途转发任务与每连接任务靠这个信号判断
    /// "网关对象没了"。`Controller` 由 `Gateway` 独占，`AppState` 只持接收端，所以
    /// drop `Controller` 必须让所有接收端看到 `Err`。
    #[tokio::test]
    async fn dropping_the_controller_closes_the_channel() {
        let controller = Controller::new();
        let mut rx = controller.subscribe();
        // 模拟"每条连接任务手里那份 Router"里的 AppState 克隆：它只有接收端。
        let per_connection = controller.subscribe();

        drop(controller);
        let verdict = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
        assert!(
            matches!(verdict, Ok(Err(_))),
            "Controller 被 drop 后通道必须关闭，否则 drop 网关后没人会醒来：{verdict:?}"
        );
        assert_eq!(
            *per_connection.borrow(),
            ShutdownPhase::Running,
            "通道关闭只是不再变化，阶段值仍可查（连接任务据此打的日志才不会撒谎）"
        );
    }
}
