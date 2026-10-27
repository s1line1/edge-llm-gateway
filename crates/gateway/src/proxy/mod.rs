//! 代理转发编排：`prepare`（认证 → 路径守卫 → body → 隧道帧）→ 选路/等头 → `forward` 回写。
//!
//! 请求准备在 `prepare`，响应回传在 `forward`；本文件只保留两段之间的编排与响应组装。

mod forward;
mod head;
mod prepare;
mod routing;
mod tunnel;
mod usage;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use proto::io::FrameReader;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

use crate::openai::error_response;
use crate::state::AppState;
use forward::{forward_body, ForwardCtx, ForwardGuard};

pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    let prepared = match prepare::prepare(&state, req).await {
        Ok(prepared) => prepared,
        Err(response) => return response,
    };
    let prepare::Prepared {
        request_id,
        request,
        model,
        prompt_est,
        key_id,
        key_name,
    } = prepared;

    let (entry, slot, recv, mut send) =
        match routing::open_and_send(&state, &model, &request, request_id).await {
            Ok(routed) => routed,
            Err(failure) => return error_response(failure.status, failure.message),
        };

    debug!(request_id, "proxying request to agent");

    // **读路径只有一条**（记录 R3）：头与体共用同一个 `FrameReader`，且它**拥有** `recv`
    // （`FrameReader::new(recv)` 是移动）。这样"读完响应头时已经预读进缓冲的体字节"会被
    // 下一阶段继续消费，而不是随临时 reader 一起丢掉；同时它天生取消安全
    // （见 `proto::io` 的 `FrameReader`），所以 `forward_body` 里的 `select!` 落败也不丢字节。
    let mut reader = FrameReader::new(recv);

    // 读取响应头：超时窗口、慢/死判据的渲染、Cancel 与 finish 全在 `head` 模块里
    // （一处改动理由 = 上游响应头契约），这里只把失败渲染成响应。
    let (status, mut out_headers) =
        match head::await_head(&state, &mut reader, &mut send, &entry, request_id).await {
            Ok(v) => v,
            Err(failure) => return error_response(failure.status, failure.message),
        };
    out_headers.retain(|(k, _)| !proto::headers::is_hop_by_hop(k.as_str()));

    // 流式回写响应体：后台任务把响应帧转进通道，HTTP 客户端从通道逐块读取。
    // 客户端断开（通道接收端被丢弃）→ 自动向 agent 发 Cancel，避免白算 token。
    // slot 守卫随任务结束释放，期间该请求计入 agent 在途并发。
    // usage 收集：提取上游 usage；无 usage（估算/取消/断流）→ 估算降级。
    let (tx, rx) = mpsc::channel::<Result<Bytes, String>>(32);
    let idle = state.policy.request_timeout;
    let op_timeout = state.policy.tunnel_op_timeout;
    let state_client_stall = state.policy.client_stall;
    let metrics = state.metrics.clone();
    let store = state.store.clone();
    // 关闭阶段的接收端：`Terminating` 时这条流要带一个明确事件收尾（见 `forward.rs`）。
    let shutdown = state.subscribe_shutdown();
    // SSE 响应是流式（usage 在每个 chunk 尾部，逐块预过滤）；非 SSE 为整包 JSON
    let is_stream = out_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream"));
    tokio::spawn(async move {
        // 守卫必须**在 `forward_body` 之前**建好：`tx` 会被移进它，而 panic 展开时我们还得有
        // 一个发送端把"这份响应不完整"送出去（复扫 B3，见 `ForwardGuard` 的文档）。
        let mut guard = ForwardGuard::new(tx.clone(), metrics.clone(), request_id);
        let ctx = ForwardCtx {
            request_id,
            tx,
            idle_timeout: idle,
            client_stall: state_client_stall,
            op_timeout,
            slot,
            metrics,
            store,
            key_id,
            key_name,
            prompt_est,
            is_stream,
            shutdown,
        };
        let end = forward_body(&mut reader, &mut send, ctx).await;
        guard.finish(end);
    });

    let mut builder = Response::builder().status(status);
    for (k, v) in out_headers {
        if let Some((name, value)) = relayable_response_header(&k, &v) {
            builder = builder.header(name, value);
        }
    }
    match builder.body(Body::from_stream(ReceiverStream::new(rx))) {
        Ok(resp) => resp,
        // 防御性分支：`status` 与每个 header 都已经过校验（`relayable_response_header` 只放行
        // 解析成功的名字/值），所以这里实际上到不了。**仍然**只回固定文案、细节进日志：
        // 这是**公开端点**，文案全仓一致（对照 `:135` 的 "internal error while parsing the
        // request body"），别把 `http::Error` 的原文当成对外契约（SL-P3-20 的同类）。
        Err(e) => {
            warn!(request_id, error = %e, "failed to build the response; returning 500");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error while building the response",
            )
        }
    }
}

/// 把隧道帧里的响应头装进对客户端的响应（记录 P3-16 的复核）。
///
/// **这里本来就没坏**：实测 `HeaderValue::from_str` 接受非 ASCII（中文 OK），真正只认可见
/// ASCII 的是 `to_str()`——坑在另外两处（网关的 `filter_headers`、agent 的响应头回传），
/// 都已改成按 UTF-8 取字节。抽成函数是为了把"非法名/非法值丢该头、不伪造值"这条行为用单测
/// 钉住（含 CR/LF 仍被拒）。
fn relayable_response_header(name: &str, value: &str) -> Option<(HeaderName, HeaderValue)> {
    let name = match HeaderName::from_bytes(name.as_bytes()) {
        Ok(n) => n,
        Err(_) => {
            warn!(
                header = name,
                "dropping a response header with an invalid name"
            );
            return None;
        }
    };
    match HeaderValue::from_str(value) {
        Ok(v) => Some((name, v)),
        Err(_) => {
            warn!(header = %name, "dropping a response header with an invalid value");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 规格（记录 P3-16）：**响应方向**也按 UTF-8 原样透传，且注入防线不变。
    #[test]
    fn relayable_response_header_keeps_utf8_values_and_still_rejects_injection() {
        let (name, value) =
            relayable_response_header("x-echo", "张三").expect("中文响应头值应当能装进响应");
        assert_eq!(name.as_str(), "x-echo");
        assert_eq!(value.as_bytes(), "张三".as_bytes());

        assert!(
            relayable_response_header("x-echo", "a\r\nX-Evil: 1").is_none(),
            "CRLF 必须仍然被拒（注入防线不许因为放宽编码而失守）"
        );
        assert!(
            relayable_response_header("bad name", "v").is_none(),
            "非法头名仍要丢"
        );
    }
}
