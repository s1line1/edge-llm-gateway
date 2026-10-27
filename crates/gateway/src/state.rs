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
use std::time::Duration;

use tokio::sync::watch;

use crate::metrics::Metrics;
use crate::options::Options;
use crate::ratelimit::{RateLimiter, TenantRateLimiter};
use crate::registry::Registry;
use crate::storage::Storage;
use crate::tenant_limits::TenantLimiter;
use crate::ui::{resolve_ui, IndexHtml};

// 关闭阶段的所有权在 `crate::shutdown`（唯一发送端 + 单向推进 + 等待窗口）。
// 这里只把类型再导出：既有 `crate::state::ShutdownPhase` 导入路径不变。
pub use crate::shutdown::ShutdownPhase;

/// 请求路径上的运行时策略：从 [`Options`] 投影一次，不含身份材料/UI/存储配置。
///
/// 为什么单独成类型（核心评估 C2）：这些值原先由 `AppState::new` 逐个手抄到 10 个 `pub` 字段，
/// 新增一个旋钮要改 5 处，漏抄一个不会编译失败。现在投影只发生在 [`RequestPolicy::from_options`]，
/// `AppState` 只持一个 `policy`；handler 通过 `state.policy.*` 读到的是同一份派生值。
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

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub store: Storage,
    /// Admin token（None 表示不启用 /admin/*）。
    pub admin_token: Option<String>,
    /// 请求路径策略（超时、并发上限、流额度）；派生只在 [`RequestPolicy::from_options`]。
    pub policy: RequestPolicy,
    pub rate_limiter: Option<RateLimiter>,
    pub tenant_rate_limiter: TenantRateLimiter,
    pub tenant_limiter: TenantLimiter,
    pub metrics: Metrics,
    /// React UI 静态目录（None = `/` 显示构建提示页）。
    pub ui: Option<PathBuf>,
    /// `ui/index.html` 的缓存读（按 mtime 校验），`ui` 为 None 时也是 None。
    /// 从 `ui` 派生而不是各自 `dir.join("index.html")`：读盘只有这一条路径。
    ///
    /// `pub(crate)` 而非 `pub`：其余字段是"配置值"，外部（`config.rs`/`main.rs`）会读；
    /// 这个字段只给 `http` 的 handler 用，没必要把 [`IndexHtml`] 带进公开 API。
    pub(crate) ui_index: Option<IndexHtml>,
    /// `ui_dir` 不可用的具体原因（None = 没配 ui_dir，或配了且可用）。
    /// 由启动时 [`resolve_ui`] 判定后写入，占位页会把它显示出来——否则用户只看到白屏/通用文案。
    pub ui_problem: Option<String>,
    /// 关闭阶段的接收端：查询与订阅都从这里出发。
    ///
    /// **发送端不在本结构里**（`shutdown::Controller` 由 `Gateway` 独占）：`AppState` 的克隆
    /// 因此不可能把 `watch` 通道钉活；`Controller` 被 drop（= `Gateway` 没了）时，所有接收端
    /// 看到 `Err`，`shutdown::wait_closed` 据此硬停连接。
    shutdown_rx: watch::Receiver<ShutdownPhase>,
}

impl AppState {
    /// 从 [`Options`] 组装请求处理状态：配置 → `AppState` 的映射与**派生只在这一处发生**。
    ///
    /// 两个派生量都不单独设旋钮：
    /// - `head_alive_window = head_timeout × 4`：连续四个窗口一次响应头都没回来，才算"不是慢，是死"；
    /// - `max_open_tunnel_streams = opts.stream_ceiling()`：0 → 默认值，与绑 QUIC 端点同一口径。
    ///
    /// `ui_dir` 的可用性判定（[`resolve_ui`]）也在这里：它是**非致命**的启动自检，
    /// 不通过就降级成占位页，并把原因交给页面自己显示。
    pub fn new(
        registry: Registry,
        store: Storage,
        metrics: Metrics,
        opts: &Options,
        shutdown_rx: watch::Receiver<ShutdownPhase>,
    ) -> Self {
        let (ui, ui_problem) = resolve_ui(opts.ui_dir.as_deref());
        let ui_index = ui
            .as_ref()
            .map(|dir| IndexHtml::new(dir.join("index.html")));
        Self {
            registry,
            store,
            // `admin_token` 的**首尾空白在这里剪掉**（复扫 D2）。不剪的话它是"配了却用不了"：
            // `Options::validate` 只拒"全是空白"，而 `admin_token: " x "` 能过校验、`/admin/*`
            // 也照样挂载（下面的挂载判据与 `admin.rs` 的比较都看这个字段），但每个管理请求都是
            // 401——因为入站凭据到不了带空白的那一步：`auth::bearer_token` 在 scheme 之后
            // `trim_start_matches(' ')`，httparse 解析头部时又 **trim trailing whitespace**
            // （它显式去掉 `' '`、`'\t'`、`'\r'`、`'\n'`，见 `httparse::parse_headers` 里那句
            // 注释）。这里剪的两端正是这组字符，而不是 `str::trim()` 的 Unicode 空白——后者会把
            // 一个**本来能用**的（比如尾随 NBSP）token 改成不能用的。
            //
            // 修好它而不是拒绝它，与 E3 的 `upstream` 尾斜杠同一口径（等价写法不该把一份合法
            // 配置判死）；空串 / 全空白仍在 `Options::validate` 里拒绝——那种剪完什么都不剩，
            // 是另一回事。
            admin_token: opts
                .admin_token
                .as_deref()
                .map(|token| token.trim_matches([' ', '\t', '\r', '\n']).to_owned()),
            policy: RequestPolicy::from_options(opts),
            rate_limiter: RateLimiter::new(opts.rate_limit_per_min),
            tenant_rate_limiter: TenantRateLimiter::new(),
            tenant_limiter: TenantLimiter::new(),
            metrics,
            ui,
            ui_index,
            ui_problem,
            shutdown_rx,
        }
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

    /// 规格（复扫 D2）：**`admin_token` 的首尾空白在装配时剪掉**，否则它是"配了却用不了"。
    ///
    /// 这条钉的是装配点：字段是 `pub`，如果有人绕过 `AppState::new` 直接塞一个带空白的值，
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
            state.admin_token.as_deref(),
            Some("tok"),
            "两端空白必须剪掉（入站凭据到不了带空白的那一步，见 `AppState::new` 的说明）"
        );

        // 内部空白是 token 的一部分，不许动
        let opts = Options {
            admin_token: Some("to k".into()),
            ..Options::default()
        };
        let state = state_with(&opts, &controller);
        assert_eq!(state.admin_token.as_deref(), Some("to k"));

        // `None`（不启用 /admin/*）不受影响
        let no_admin = state_with(&Options::default(), &controller);
        assert!(no_admin.admin_token.is_none());
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
