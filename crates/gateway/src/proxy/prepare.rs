//! 请求侧的"准备"：认证 → 路径守卫 → 读 body → 解析 facts → 构造隧道帧。
//!
//! 从 `proxy/mod.rs` 拆出来的理由：这是一条**有硬顺序**的流水线（认证必须在读 body 之前、
//! 路径守卫必须在读 body 之前），而顺序原先只写在 handler 的注释里。把这一段收成一个函数后，
//! `proxy` 只剩"选路 → 等头 → 回写"的编排，顺序由调用点固定下来。
//!
//! 失败一律返回**已经渲染好的** `Response`：状态码/文案是外部契约，仍由 `openai::error_response`
//! 统一构造。

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use proto::Frame;
use tracing::{error, warn};

use crate::{
    auth::authenticate,
    body::{read_body_with_stall, BodyRead, MAX_REQUEST_BODY},
    openai::error_response,
    state::RequestRuntime,
    usage_meter,
};

/// 解析请求体的失败原因：`Invalid` 是客户端的问题（400），`Internal` 是网关自己的（500）。
#[derive(Debug, PartialEq, Eq)]
enum FactsError {
    Invalid,
    Internal,
}

/// 大 body 的解析挪去阻塞池的最小体积。
///
/// `request_facts` 是一次**全量 JSON 解析**：16MiB 实测 ~77ms（debug 构建），压在 async worker
/// 上会连带卡住同一个线程上的其它请求（H6 说的队头阻塞）。小 body（聊天请求常见几 KB）原地
/// 解析——每次请求多一次 `spawn_blocking` 的线程池往返还更亏。阈值是**实测权衡**，不是协议值。
const PARSE_OFFLOAD_MIN_BYTES: usize = 256 * 1024;

/// 取请求侧解析结果：大 body 走阻塞池，小 body 原地解析。
async fn request_facts_for(
    body: &axum::body::Bytes,
) -> Result<usage_meter::RequestFacts, FactsError> {
    if body.len() < PARSE_OFFLOAD_MIN_BYTES {
        return usage_meter::request_facts(body).map_err(|_| FactsError::Invalid);
    }
    // `Bytes` 克隆是引用计数：把所有权移进阻塞任务**不拷贝** body 内容
    let owned = body.clone();
    match tokio::task::spawn_blocking(move || usage_meter::request_facts(&owned)).await {
        Ok(facts) => facts.map_err(|_| FactsError::Invalid),
        Err(e) => {
            error!("request body parsing task failed: {e}");
            Err(FactsError::Internal)
        }
    }
}

/// `prepare` 的产物：路由/转发需要的一切，且**请求帧已经构造好**（重试换连接不换内容）。
pub(super) struct Prepared {
    pub request_id: u64,
    pub request: Frame,
    pub model: String,
    pub prompt_est: u64,
    pub key_id: String,
    pub key_name: String,
    pub tenant_id: String,
    pub tenant_slot: crate::access::limits::TenantSlot,
}

/// 按固定顺序准备一次代理请求；任何一步失败都返回已经渲染好的响应。
pub(super) async fn prepare(state: &RequestRuntime, req: Request) -> Result<Prepared, Response> {
    // 先取 method/uri/headers，body 留到**认证之后再读**：
    // 以前 `Bytes` 是提取器，于是未认证的请求也能让网关先缓冲 16MB（认证在 handler 里，
    // 比提取器晚一步）。现在认证在最前，读 body 在后，顺带把这个放大面收掉。
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    // 隧道 id 与 HTTP 层同源（crate::request_id）：middleware 已把规范化的 req-{n}
    // 写回入站 headers，UUID 客户端也不例外，于是两边不会再各自计数、周期性撞号。
    let request_id = crate::request_id::tunnel_id_from_headers(&headers);

    // 认证 + 限流（per-key 令牌桶）：拿不到身份的唯一出路就是把它还给客户端。
    let key = match authenticate(state, &headers).await {
        Ok(key) => key,
        Err(rejection) => return Err(rejection.into_response()),
    };

    let Some(tenant) = state.store.tenant(&key.tenant_id) else {
        return Err(error_response(StatusCode::FORBIDDEN, "tenant disabled"));
    };
    let tenant_slot = match state
        .tenant_limiter
        .try_enter(tenant.id(), tenant.max_concurrent_requests())
    {
        Ok(slot) => slot,
        Err(_) => {
            return Err(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "tenant concurrency limit reached",
            ))
        }
    };

    // 路径守卫：**认证之后、读 body 之前**。放在这里有两个理由：① 未认证的探测拿不到
    // 路径校验的信息（先 401）；② 越权路径不必先让我们读进 16MiB 的 body。
    //
    // 判据本身在 `proto::path::safe_upstream_path`——**与 agent 侧共享同一份实现**：同一条
    // 规则的两道防线（这里拒一次、agent 拼上游 URL 前再拒一次），两份实现会漂移，而漂移的
    // 方向恰好会是"后面那道更松"，纵深防御就静默失效了。网关这一步管的是**越权请求的
    // 状态码**（客户端拿 400），agent 那一步管的是**隧道另一端不再受信时的兜底**。
    // 详见 `PROJECT_SCAN` P1-2。
    let Some(guarded_path) = proto::path::safe_upstream_path(uri.path()) else {
        warn!(
            request_id,
            path = %uri.path(),
            "rejecting request: path cannot be forwarded safely (dot segment, backslash or encoded separator)"
        );
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid request path",
        ));
    };
    // 通过守卫之后才拼 query：原样转发（query 不参与点段判定）
    let path = match uri.query() {
        Some(q) => format!("{guarded_path}?{q}"),
        None => guarded_path.to_string(),
    };

    // 读请求体：停滞/超限/读失败各自有明确状态码，且**都会归还准入票据**（随本函数返回而
    // Drop）——这正是修掉"槽位永久泄漏"的地方。
    let body =
        match read_body_with_stall(req.into_body(), state.policy.client_stall, MAX_REQUEST_BODY)
            .await
        {
            BodyRead::Body(b) => b,
            BodyRead::Stalled => {
                state.metrics.record_client_stall("request-body");
                warn!(
                request_id,
                stall_ms = state.policy.client_stall.as_millis(),
                "client stalled while sending the request body; dropping the request and its slot"
            );
                return Err(error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "client stalled while sending the request body",
                ));
            }
            BodyRead::TooLarge => {
                return Err(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                ))
            }
            BodyRead::Failed(e) => {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("request body read failed: {e}"),
                ))
            }
        };
    // 一次解析同时拿到路由要的 model 与 prompt 估算（H6：以前这里解析一遍、
    // 下面估算又解析一遍）。解析失败/缺 model 的语义与拆分前一致 → 400。
    let facts = match request_facts_for(&body).await {
        Ok(f) => f,
        Err(FactsError::Invalid) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "model is required in request body",
            ))
        }
        // 阻塞池任务 panic/被取消：这是网关自己的故障，别让客户端以为是自己 body 的问题
        Err(FactsError::Internal) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error while parsing the request body",
            ))
        }
    };
    let model = facts.model;
    // prompt 估算（仅在无 usage 时使用）：来自上面那次解析的字符数，**不再解析一遍**
    let prompt_est = usage_meter::estimate_tokens_from_chars(facts.prompt_chars).max(1);
    // request_id 在函数最开头就算好了（因为它要出现在"读 body 停滞"这类早期日志里）。
    // 隧道 request_id 与 HTTP 层 x-request-id 同源（crate::request_id）：
    // middleware 注入规范化的 req-{n}，本函数沿用它，响应头/日志/隧道帧三方同一个数字。
    // 请求帧在选路之前就构造好：重试换的是连接，请求内容不变（body 已整包在手，可重放）。
    let request = Frame::ProxyRequest {
        request_id,
        method: method.to_string(),
        path,
        headers: filter_headers(&headers),
        body,
    };

    Ok(Prepared {
        request_id,
        request,
        model,
        prompt_est,
        key_id: key.key_id,
        key_name: key.key_name,
        tenant_id: key.tenant_id,
        tenant_slot,
    })
}

/// 过滤要放进隧道帧的头：剔除逐跳头**与调用方凭据**。
///
/// 凭据（`authorization` / `cookie`）只在「客户端 ↔ 网关」这一跳有意义：客户端持有的是
/// **网关签发**的 API key（对全部模型有效、能打公网网关），而 edge 与上游属于另一个信任域，
/// 三种上游（Ollama/vLLM/llama.cpp）又都不认证——透传零收益、纯风险：edge 一旦被攻破，
/// 攻击者白得一把可用的公网凭据，edge / 上游日志里还会留下吊销不掉的副本。
/// 上游确实需要认证时，应在 **agent 侧**配置上游自己的凭据。
///
/// 注意凭据**不是**逐跳头（RFC 语义上端到端），因此这里用两条独立规则，
/// 规则常量见 `proto::headers`。
fn filter_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let connection = proto::headers::connection_tokens(
        headers
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str(), value))),
    );
    headers
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if !proto::headers::is_forwardable(name, &connection) {
                return None;
            }
            // 记录 P3-16：**不能**用 `to_str()`——它只接受可见 ASCII，而 HTTP 允许 obs-text
            // （0x80–0xFF），于是"UTF-8 头值"（中文名、中文文件名等很常见）会被判失败。
            // 以前那句 `to_str().unwrap_or_default()` 把它变成**空串**：上游看到的是"有这个头、
            // 值为空"，与"没有这个头"是两回事（可能让上游走错分支，签名类头更糟）。
            // 帧里本来就是 `String`，UTF-8 完全装得下 ⇒ 按 UTF-8 原样透传。
            match std::str::from_utf8(v.as_bytes()) {
                Ok(value) => Some((name.to_string(), value.to_string())),
                Err(_) => {
                    // 真·非 UTF-8 的字节装不进 `String`（改线格式属冻结范围）⇒ 只能丢这个头。
                    // 但**不伪造空值**。值本身可能是任意二进制，故只记头名与长度。
                    warn!(
                        header = name,
                        len = v.as_bytes().len(),
                        "dropping a header whose value is not valid UTF-8 (it cannot ride the frame's String)"
                    );
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// 规格（记录 P3-16）：**非 ASCII（中文 UTF-8）头值必须逐字透传**，不许被清成空串。
    #[test]
    fn filter_headers_keeps_utf8_header_values_verbatim() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-user-name",
            HeaderValue::from_bytes("张三".as_bytes()).unwrap(),
        );
        assert_eq!(
            filter_headers(&headers),
            vec![("x-user-name".to_string(), "张三".to_string())],
            "UTF-8 头值必须原样透传（修好前这里会是空串）"
        );
    }

    /// 规格（记录 P3-16 的另一半）：**真·非 UTF-8** 的值丢头，而不是伪造空值。
    #[test]
    fn filter_headers_drops_non_utf8_values_instead_of_emptying_them() {
        let mut headers = HeaderMap::new();
        headers.insert("x-binary", HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            !names.contains(&"x-binary"),
            "非 UTF-8 值必须丢头，不能留下空值：{out:?}"
        );
        assert!(names.contains(&"content-type"), "其它头照旧转发：{out:?}");
    }

    #[test]
    fn filter_headers_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("42"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"));
        for hop in proto::headers::HOP_BY_HOP {
            assert!(!names.contains(hop), "hop-by-hop header leaked: {hop}");
        }
    }

    /// 规格：调用方的凭据**不得**随隧道帧离开网关。
    #[test]
    fn filter_headers_never_forwards_client_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer sk-secret"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=topsecret"));
        headers.insert("x-api-key", HeaderValue::from_static("sk-upstream"));

        let out = filter_headers(&headers);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"content-type"), "普通头照旧转发: {names:?}");
        assert!(
            !names.contains(&"authorization"),
            "网关自己的 API key 不得进入隧道帧: {names:?}"
        );
        assert!(
            !names.contains(&"cookie"),
            "客户端 cookie 同样不得进入隧道帧: {names:?}"
        );
        let joined: String = out
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join("|");
        assert!(
            !joined.contains("sk-secret") && !joined.contains("topsecret"),
            "凭据值不得出现在隧道帧里: {joined}"
        );
    }

    /// 规格（H6）：**大 body 走阻塞池、结果与小 body 一致**。
    #[tokio::test]
    async fn request_facts_for_offloads_large_bodies_and_keeps_the_same_result() {
        let filler = "x".repeat(PARSE_OFFLOAD_MIN_BYTES);
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "qwen2.5",
            "messages": [{"role": "user", "content": filler}],
        }))
        .unwrap();
        assert!(
            body.len() >= PARSE_OFFLOAD_MIN_BYTES,
            "前提：这个 body 必须走阻塞池那条路（实际 {}）",
            body.len()
        );
        let bytes = axum::body::Bytes::from(body);
        let facts = request_facts_for(&bytes)
            .await
            .expect("大 body 也必须解析成功");
        assert_eq!(facts.model, "qwen2.5");
        assert_eq!(
            facts.prompt_chars, PARSE_OFFLOAD_MIN_BYTES as u64,
            "字符数必须与小 body 路径一致（同样是 messages[].content 的长度）"
        );

        let small = axum::body::Bytes::from_static(br#"{"model":"m","messages":[]}"#);
        assert_eq!(request_facts_for(&small).await.expect("小 body").model, "m");
        let bad = axum::body::Bytes::from(vec![b'x'; PARSE_OFFLOAD_MIN_BYTES]);
        assert!(
            matches!(request_facts_for(&bad).await, Err(FactsError::Invalid)),
            "非法 JSON 必须报 Invalid（400），不能报 Internal（500）"
        );
    }

    /// 规格：路由只认**顶层**的 `model` 字符串。
    #[test]
    fn routing_takes_the_top_level_model_string_only() {
        let model = |b: &[u8]| crate::usage_meter::request_facts(b).map(|f| f.model);
        assert_eq!(
            model(br#"{"model":"qwen2.5","messages":[]}"#).unwrap(),
            "qwen2.5"
        );
        assert!(model(br#"{"messages":[{"role":"user","content":"model?"}]}"#).is_err());
        assert!(model(br#"{"messages":[]}"#).is_err(), "缺失 model");
        assert!(model(br#"{"model":123}"#).is_err(), "非字符串 model");
        assert!(model(br#"{"model":""}"#).is_err(), "空串 model");
        assert!(model(b"not json").is_err(), "非法 JSON");
    }

    /// 规格（S2-10）：`Connection` 点名的字段与 `x-api-key` 都必须被剔除。
    #[test]
    fn filter_headers_strips_connection_named_fields_and_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("x-internal"));
        headers.insert("x-internal", HeaderValue::from_static("secret"));
        headers.insert("x-api-key", HeaderValue::from_static("sk-upstream"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let out = filter_headers(&headers);
        assert_eq!(
            out,
            vec![("content-type".to_string(), "application/json".to_string())],
            "only the end-to-end header may survive: {out:?}"
        );
    }
}
