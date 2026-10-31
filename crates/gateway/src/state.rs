//! 请求处理共享状态：[`AppState`] —— 路由、代理、管理接口与认证都用它。
//!
//! 为什么它不在 `http` 模块里：它曾是"路由模块"的一部分，而真正的消费者跨越了每一层
//! （`proxy`、`auth`、`admin`、metrics 中间件）。那样会让路由层成为所有人的上游，
//! 并形成 `http <-> proxy` 的模块环。搬到这里之后那三个层只**读**它，环没有了：
//! `state <- {http, proxy, auth, admin}`。
//!
//! **反向边已消**：`new` 的入参 [`Options`] 住在叶子模块 [`crate::options`]，本模块
//! **不再依赖 `gateway.rs`**——原先那条 `state <-> gateway` 随 `Options` 搬家一起消掉了。
//! `gateway::Options` 这个既有公开路径由 `gateway.rs` 再导出继续保住（`lib.rs` 与
//! `tests/e2e` 按它引用）。
//!
//! `new` 承担**全部派生**（`head_alive_window`、`RateLimiter`、`stream_ceiling`、UI 判定），
//! 所以每个派生量在整仓库只存在一处；调用方只给一个 [`Options`]。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use tokio::sync::watch;

use crate::access::limits::{LoginLimiter, RateLimiter, TenantLimiter, TenantRateLimiter};
use crate::metrics::Metrics;
use crate::options::Options;
use crate::registry::Registry;
use crate::storage::Storage;
use crate::task_scope::TaskScope;
use crate::ui::{resolve_ui, IndexHtml};

// 关闭阶段的所有权在 `crate::shutdown`（唯一发送端 + 单向推进 + 等待窗口）。
// 这里只把类型再导出：既有 `crate::state::ShutdownPhase` 导入路径不变。
pub use crate::shutdown::ShutdownPhase;

/// 请求路径上的运行时策略：从 [`Options`] 投影一次，不含身份材料/UI/存储配置。
///
/// 这些值原先由 `AppState::new` 逐个手抄到多个公开字段；新增一个旋钮要改多处，
/// 漏抄一个不会编译失败。现在投影只发生在 [`RequestPolicy::from_options`]，
/// 请求侧只持一个 `policy`；handler 通过 `RequestRuntime.policy` 读到同一份派生值。
#[derive(Debug, Clone, Copy)]
pub struct RequestPolicy {
    /// 单次请求转发空闲超时（逐帧）。SSE 长流靠“有帧就不超时”活着。
    pub request_timeout: Duration,
    /// 心跳过期阈值：注册表据此判断“还能不能路由”。
    pub agent_stale_after: Duration,
    /// 隧道控制操作超时（打开流 / 发送请求头 / 取消帧）。
    pub tunnel_op_timeout: Duration,
    /// 等待上游响应头（首字节）的超时。
    pub head_timeout: Duration,
    /// 摘除一条连接后，等它在途请求收尾的宽限。默认与 `head_timeout` 相等；配得更短时
    /// `Gateway::start` 会 WARN（仍在合法等响应头的请求会被宽限掐断）。
    pub evict_close_grace: Duration,
    /// 「响应头静默」判据里对端还在说话时的静默容忍上限。
    pub head_silent_grace: Duration,
    /// 客户端停滞阈值：请求体/响应体两个方向“完全没动静”多久就放弃。
    pub client_stall: Duration,
    /// 响应头超时的“忙/死”判据窗口：由 `head_timeout × 4` 派生，不单独设旋钮。
    pub head_alive_window: Duration,
    /// HTTP 全局在途请求上限（0 = 不限；per-key 限流之外的总闸门）。
    pub max_concurrent_requests: u32,
    /// 每条 agent 连接允许的同时在途隧道流数（**网关这一侧**的上限）。
    ///
    /// **语义边界（S2-18，待核）**：这是本地上限，不是 `min(本地, 对端广告)`；两者不等时
    /// `max_concurrency == 0` 的 agent 在 `[对端, 本地)` 区间会被判“死”而不是“忙”。
    pub max_open_tunnel_streams: u32,
}

impl RequestPolicy {
    /// 唯一的投影点：`Options` → 请求路径策略，两个派生量（`head_alive_window` /
    /// `stream_ceiling()`）也在这里算。新增旋钮只改这里与 `Options`/`config`。
    fn from_options(opts: &Options) -> Self {
        Self {
            request_timeout: opts.request_timeout,
            agent_stale_after: opts.agent_stale_after,
            tunnel_op_timeout: opts.tunnel_op_timeout,
            head_timeout: opts.head_timeout,
            evict_close_grace: opts.evict_close_grace,
            head_silent_grace: opts.head_silent_grace,
            client_stall: opts.client_stall,
            head_alive_window: opts.head_alive_window(),
            max_concurrent_requests: opts.max_concurrent_requests,
            max_open_tunnel_streams: opts.stream_ceiling(),
        }
    }
}

/// Request-path capabilities. Handlers receive this narrow context, not the whole app.
#[derive(Clone)]
pub struct RequestRuntime {
    pub(crate) registry: Registry,
    pub(crate) shutdown_rx: watch::Receiver<ShutdownPhase>,
    pub(crate) store: Storage,
    pub(crate) policy: RequestPolicy,
    pub(crate) rate_limiter: Option<RateLimiter>,
    pub(crate) tenant_rate_limiter: TenantRateLimiter,
    pub(crate) tenant_limiter: TenantLimiter,
    pub(crate) metrics: Metrics,
    pub(crate) forward_tasks: std::sync::Arc<TaskScope>,
}

/// Admin/dashboard capabilities: credentials, sessions, and audit-facing stores.
#[derive(Clone)]
pub struct AdminRuntime {
    pub(crate) store: Storage,
    pub(crate) registry: Registry,
    pub(crate) policy: RequestPolicy,
    pub(crate) admin_token: Option<String>,
    pub(crate) session_ttl_secs: u64,
    pub(crate) session_cookie_secure: bool,
    pub(crate) bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) rate_limiter: Option<RateLimiter>,
    pub(crate) tenant_rate_limiter: TenantRateLimiter,
    pub(crate) tenant_limiter: TenantLimiter,
    pub(crate) login_limiter: LoginLimiter,
    pub(crate) pki: Option<Arc<crate::pki::PkiService>>,
}

/// UI-only capabilities. Kept separate so public request handlers cannot reach index files.
#[derive(Clone)]
pub struct UiRuntime {
    pub(crate) ui: Option<PathBuf>,
    pub(crate) ui_index: Option<IndexHtml>,
    pub(crate) ui_problem: Option<String>,
}

/// Process-wide axum state. All fields are private; consumers extract a capability group.
#[derive(Clone)]
pub struct AppState {
    request: RequestRuntime,
    admin: AdminRuntime,
    ui: UiRuntime,
    shutdown_rx: watch::Receiver<ShutdownPhase>,
}

#[cfg(test)]
impl std::ops::Deref for AppState {
    type Target = RequestRuntime;
    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

#[cfg(test)]
impl std::ops::DerefMut for AppState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

impl RequestRuntime {
    pub fn subscribe_shutdown(&self) -> watch::Receiver<ShutdownPhase> {
        self.shutdown_rx.clone()
    }
}

impl FromRef<AppState> for RequestRuntime {
    fn from_ref(state: &AppState) -> Self {
        state.request.clone()
    }
}

impl FromRef<AppState> for AdminRuntime {
    fn from_ref(state: &AppState) -> Self {
        state.admin.clone()
    }
}

impl FromRef<AppState> for UiRuntime {
    fn from_ref(state: &AppState) -> Self {
        state.ui.clone()
    }
}

impl AppState {
    /// Build the process state and all derived values in one place.
    pub fn new(
        registry: Registry,
        store: Storage,
        metrics: Metrics,
        opts: &Options,
        shutdown_rx: watch::Receiver<ShutdownPhase>,
    ) -> Self {
        let registry_clone = registry.clone();
        let (ui, ui_problem) = resolve_ui(opts.ui_dir.as_deref());
        let ui_index = ui
            .as_ref()
            .map(|dir| IndexHtml::new(dir.join("index.html")));
        let rate_limiter = RateLimiter::new(opts.rate_limit_per_min);
        let tenant_rate_limiter = TenantRateLimiter::new();
        let tenant_limiter = TenantLimiter::new();
        let request = RequestRuntime {
            registry,
            store: store.clone(),
            policy: RequestPolicy::from_options(opts),
            rate_limiter: rate_limiter.clone(),
            tenant_rate_limiter: tenant_rate_limiter.clone(),
            tenant_limiter: tenant_limiter.clone(),
            metrics,
            forward_tasks: std::sync::Arc::new(TaskScope::new("forward")),
            shutdown_rx: shutdown_rx.clone(),
        };
        let admin = AdminRuntime {
            store,
            registry: registry_clone,
            policy: RequestPolicy::from_options(opts),
            admin_token: opts
                .admin_token
                .as_deref()
                .map(|token| token.trim_matches([' ', '\t', '\r', '\n']).to_owned()),
            session_ttl_secs: opts.session_ttl_secs,
            session_cookie_secure: opts.session_cookie_secure.unwrap_or(opts.https.is_some()),
            bootstrap_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter,
            tenant_rate_limiter,
            tenant_limiter,
            login_limiter: LoginLimiter::new(),
            pki: None,
        };
        let ui = UiRuntime {
            ui,
            ui_index,
            ui_problem,
        };
        Self {
            request,
            admin,
            ui,
            shutdown_rx,
        }
    }

    pub(crate) fn request(&self) -> &RequestRuntime {
        &self.request
    }

    pub(crate) fn admin(&self) -> &AdminRuntime {
        &self.admin
    }

    pub(crate) fn task_scope(&self) -> std::sync::Arc<TaskScope> {
        self.request.forward_tasks.clone()
    }

    pub(crate) fn ui(&self) -> &UiRuntime {
        &self.ui
    }

    pub(crate) fn set_pki(&mut self, pki: Option<Arc<crate::pki::PkiService>>) {
        self.admin.pki = pki;
    }

    #[cfg(test)]
    pub(crate) fn admin_mut(&mut self) -> &mut AdminRuntime {
        &mut self.admin
    }

    #[cfg(test)]
    pub(crate) fn ui_mut(&mut self) -> &mut UiRuntime {
        &mut self.ui
    }

    /// 测试专用：没有 `Gateway` 推进关闭，但需要一个**保持打开**的接收端。
    ///
    /// 这里泄漏一个 `watch::Sender`（`mem::forget`），让通道不会在测试中途关闭；生产路径
    /// 只走 [`AppState::new`]（发送端由 `Gateway` 的 `shutdown::Controller` 独占）。
    #[cfg(test)]
    pub(crate) fn new_for_test(
        registry: Registry,
        store: Storage,
        metrics: Metrics,
        opts: &Options,
    ) -> Self {
        let (tx, rx) = watch::channel(ShutdownPhase::Running);
        std::mem::forget(tx);
        Self::new(registry, store, metrics, opts, rx)
    }

    /// 当前关闭阶段（只读）。给"探针要不要报不健康"这类判断用。
    pub fn shutdown_phase(&self) -> ShutdownPhase {
        *self.shutdown_rx.borrow()
    }

    /// 订阅关闭阶段的变化：每个在途响应各持一个接收端（`Gateway` 用 `Draining` 停 accept、
    /// 用 `Terminating` 给在途 SSE 一个明确的收尾事件）。
    pub fn subscribe_shutdown(&self) -> watch::Receiver<ShutdownPhase> {
        self.shutdown_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown;

    fn state_with(opts: &Options, controller: &shutdown::Controller) -> AppState {
        AppState::new(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            opts,
            controller.subscribe(),
        )
    }

    /// 规格（Phase 1）：请求、管理、UI 三个能力组必须能从同一个 `AppState` 独立提取。
    ///
    /// 这条钉的是边界本身：axum handler 只拿自己需要的组，而不是整个 `AppState`。
    #[test]
    fn capability_runtimes_are_extractable_and_separate() {
        let controller = shutdown::Controller::new();
        let opts = Options {
            admin_token: Some("admin-token".into()),
            ..Options::default()
        };
        let state = state_with(&opts, &controller);

        let request = RequestRuntime::from_ref(&state);
        let admin = AdminRuntime::from_ref(&state);
        let ui = UiRuntime::from_ref(&state);

        assert_eq!(request.policy.max_concurrent_requests, 0);
        assert_eq!(admin.admin_token.as_deref(), Some("admin-token"));
        assert_eq!(
            admin.policy.max_concurrent_requests,
            request.policy.max_concurrent_requests
        );
        assert!(ui.ui.is_none());
        assert!(ui.ui_index.is_none());
    }

    /// 规格（复扫 D2）：**`admin_token` 的首尾空白在装配时剪掉**，否则它是"配了却用不了"。
    ///
    /// 这条钉的是装配点：能力组字段是私有的，如果有人绕过 `AppState::new` 直接构造状态，
    /// 鉴权仍然会 401——但那不是配置作者的路径，`Options::validate` 也拦不住空白（只拦全空白）。
    /// 走完整路由的版本在 `admin::tests::a_padded_admin_token_still_authenticates`。
    #[test]
    fn a_padded_admin_token_is_trimmed_when_the_state_is_built() {
        let controller = shutdown::Controller::new();
        let opts = Options {
            admin_token: Some("  tok\t".into()),
            ..Options::default()
        };
        let state = state_with(&opts, &controller);
        assert_eq!(
            state.admin().admin_token.as_deref(),
            Some("tok"),
            "两端空白必须剪掉（入站凭据到不了带空白的那一步，见 `AppState::new` 的说明）"
        );

        // 内部空白是 token 的一部分，不许动
        let opts = Options {
            admin_token: Some("to k".into()),
            ..Options::default()
        };
        let state = state_with(&opts, &controller);
        assert_eq!(state.admin().admin_token.as_deref(), Some("to k"));

        // `None`（不启用 /admin/*）不受影响
        let no_admin = state_with(&Options::default(), &controller);
        assert!(no_admin.admin().admin_token.is_none());
    }

    /// 规格（并集评估 §2 S3）：关闭阶段**可查、可订阅**，但推进阶段的能力只属于
    /// `shutdown::Controller`（`Gateway` 独占）；`AppState` 只持接收端。
    ///
    /// 这条钉的是查询/订阅接口的行为：查询反映当前阶段，订阅端能收到后续变化。
    #[test]
    fn shutdown_phase_is_queryable_and_subscribable() {
        let controller = shutdown::Controller::new();
        let state = state_with(&Options::default(), &controller);
        assert_eq!(state.shutdown_phase(), ShutdownPhase::Running);

        let mut rx = state.subscribe_shutdown();
        controller.begin_drain();
        assert_eq!(state.shutdown_phase(), ShutdownPhase::Draining);
        assert_eq!(*rx.borrow_and_update(), ShutdownPhase::Draining);

        // 订阅者是**独立**接收端：第二个订阅者只看到自己订阅之后的变化
        let mut rx2 = state.subscribe_shutdown();
        controller.terminate();
        assert_eq!(*rx.borrow_and_update(), ShutdownPhase::Terminating);
        assert_eq!(*rx2.borrow_and_update(), ShutdownPhase::Terminating);
    }

    /// 规格（复扫 D5）：**`AppState` 及其克隆不得把关闭通道钉活**。
    ///
    /// 发送端只有 `Gateway` 手里的 `shutdown::Controller` 一份；`AppState` 只持接收端。
    /// 如果 `AppState` 也留着一个发送端，那么每条连接任务手里的 Router 都会把它钉活
    /// ⇒ `drop(Gateway)` 之后谁都看不到关闭：在途响应不会收尾、已接受的空闲连接要挂到
    /// `client_stall`（默认 60s）。
    ///
    /// 判据写成 `changed()` 返回 `Err`：它只可能在**所有发送端消失**时发生。
    #[tokio::test]
    async fn app_state_does_not_pin_the_shutdown_channel() {
        let controller = shutdown::Controller::new();
        let state = state_with(&Options::default(), &controller);
        let mut rx = state.subscribe_shutdown();

        // "每条连接任务手里那份 Router"里的 AppState 克隆：它只有接收端。
        let per_connection = state.clone();
        // `Gateway` 的角色：drop 唯一持有发送端的 Controller。
        drop(controller);

        // 带超时：判据本身就是"通道关了"，而这个缺陷的形态是"永远关不了"——不设超时的话
        // 这条测试会挂到被外部打断，而不是给出一个干净的红（`Err(Elapsed)` 直接说明原因）。
        let verdict = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
        assert!(
            matches!(verdict, Ok(Err(_))),
            "AppState 或其克隆仍持有发送端 ⇒ 通道不会关闭，drop 网关后没人会醒来：{verdict:?}"
        );
        assert_eq!(
            per_connection.shutdown_phase(),
            ShutdownPhase::Running,
            "通道关闭只是不再变化，阶段值仍可查（连接任务据此打的日志才不会撒谎）"
        );
    }
}
