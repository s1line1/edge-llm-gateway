//! Admin API：运行时签发 / 列出 / 吊销 API Key。
//! 所有 /admin/* 请求都需要 `Authorization: Bearer <--admin-token>`。

use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal};
use crate::state::AppState;
use crate::storage::{TenantError, TenantPatch, UserRole};

/// admin 500 的**细节进日志、响应体只留固定文案**（SL-P3-20）。
///
/// 响应体是给调用方的稳定契约（`openai::error_response` 的文案全仓一致；公开路径连内网地址都
/// 不带），而 `{e}` 里可能是 rusqlite/io 的原文（常含 keys.db 路径）或 `JoinError` 的 panic
/// 载荷。**细节不能丢**：它原来只存在于响应体里，所以这里必须补一条日志 —— 否则就成了"把
/// 诊断信息从唯一的出口拿掉"（`admin.rs` 在这之前一行 log 都没有）。
///
/// `request_id` 取自入站头：`request_id_middleware` 已把规范化后的 id 写回 headers，所以这条
/// 日志能与访问日志对账。
fn log_admin_failure(headers: &HeaderMap, error: &dyn std::fmt::Display, what: &str) {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    error!(request_id, error = %error, "{what}");
}

/// 列出所有动态 key（不暴露明文；明文不落盘后无法显示真实前缀，用固定掩码）。
/// 每项附带该 key 的用量汇总（无记录时为 0）。
pub async fn list_keys(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    keys_json(&state, &principal, None)
}

#[derive(Debug, Deserialize)]
pub struct TenantFilter {
    tenant_id: Option<String>,
}

pub async fn list_keys_filtered(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<TenantFilter>,
) -> Response {
    keys_json(&state, &principal, query.tenant_id.as_deref())
}

fn keys_json(state: &AppState, principal: &Principal, tenant_filter: Option<&str>) -> Response {
    if let Err(e) = authorize(principal, Action::KeyRead, tenant_filter) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(principal, tenant_filter) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let records = match principal.role {
        UserRole::User => {
            let (Some(tenant), Some(owner)) = (tenant, principal.user_id.as_deref()) else {
                return crate::openai::error_response(StatusCode::FORBIDDEN, "permission denied");
            };
            state.store.list_for_owner(&tenant, owner)
        }
        _ => match tenant {
            Some(tenant) => state.store.list_for_tenant(&tenant),
            None => state.store.list(),
        },
    };
    let out: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            let usage = state.store.usage_of(r.id());
            json!({
                "id": r.id(),
                "tenant_id": r.tenant_id(),
                "tenant_name": state.store.tenant(r.tenant_id()).map(|t| t.name().to_string()),
                "owner_user_id": r.owner_user_id(),
                "owner_username": r.owner_user_id().and_then(|id| state.store.user(id)).map(|u| u.username().to_string()),
                "name": r.name(),
                "created_at": r.created_at(),
                "enabled": r.enabled(),
                "prefix": "sk-••••",
                "usage": usage.map(|u| json!({
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "total_tokens": u.total_tokens,
                    "requests": u.requests,
                    "estimated_requests": u.estimated_requests,
                    "last_used_at": u.last_used_at,
                })).unwrap_or_else(|| json!({
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "requests": 0,
                    "estimated_requests": 0,
                    "last_used_at": 0,
                })),
            })
        })
        .collect();
    Json(json!(out)).into_response()
}

/// 全部 key 的用量汇总（含已吊销 key 的历史记录，可审计）。
pub async fn usage_route(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    usage_json(&state, &principal, None)
}

pub async fn usage_filtered(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<TenantFilter>,
) -> Response {
    usage_json(&state, &principal, query.tenant_id.as_deref())
}

fn usage_json(state: &AppState, principal: &Principal, tenant_filter: Option<&str>) -> Response {
    if let Err(e) = authorize(principal, Action::UsageRead, tenant_filter) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(principal, tenant_filter) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let rows = match principal.role {
        UserRole::User => {
            let (Some(tenant), Some(owner)) = (tenant, principal.user_id.as_deref()) else {
                return crate::openai::error_response(StatusCode::FORBIDDEN, "permission denied");
            };
            state.store.usage_for_owner(&tenant, owner)
        }
        _ => match tenant {
            Some(tenant) => state.store.usage_for_tenant(&tenant),
            None => state.store.usage_snapshot(),
        },
    };
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|u| {
            json!({
                "key_id": u.key_id,
                "tenant_id": u.tenant_id,
                "name": u.name,
                "prompt_tokens": u.prompt_tokens,
                "completion_tokens": u.completion_tokens,
                "total_tokens": u.total_tokens,
                "requests": u.requests,
                "estimated_requests": u.estimated_requests,
                "last_used_at": u.last_used_at,
            })
        })
        .collect();
    Json(json!(out)).into_response()
}

/// 创建 key，返回明文（仅此一次展示；此后只存 argon2 哈希）。
pub async fn create_key(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();
    if name.chars().count() > 64 {
        return crate::openai::error_response(StatusCode::BAD_REQUEST, "name too long");
    }
    let requested = body.get("tenant_id").and_then(|v| v.as_str());
    let tenant_id = match principal.role {
        UserRole::SuperAdmin => requested
            .unwrap_or(crate::storage::DEFAULT_TENANT_ID)
            .to_string(),
        _ => match effective_tenant(&principal, requested) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return crate::openai::error_response(StatusCode::FORBIDDEN, "permission denied")
            }
            Err(e) => return rbac_response(e),
        },
    };
    if let Err(e) = authorize(&principal, Action::KeyWrite, Some(&tenant_id)) {
        return rbac_response(e);
    }
    let owner = match principal.role {
        UserRole::User => principal.user_id.clone(),
        UserRole::SuperAdmin => body
            .get("owner_user_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        UserRole::TenantAdmin => None,
    };
    if let Some(owner_id) = owner.as_deref() {
        let Some(owner_user) = state.store.user(owner_id) else {
            return crate::openai::error_response(StatusCode::BAD_REQUEST, "unknown key owner");
        };
        if owner_user.tenant_id() != Some(tenant_id.as_str()) {
            return crate::openai::error_response(
                StatusCode::BAD_REQUEST,
                "key owner must belong to the same tenant",
            );
        }
    }
    let Some(tenant) = state.store.tenant(&tenant_id) else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "tenant not found");
    };
    if !tenant.enabled() {
        return crate::openai::error_response(StatusCode::BAD_REQUEST, "tenant is disabled");
    }
    let store = state.store.clone();
    let created = match tokio::task::spawn_blocking(move || {
        store.create_in(&tenant_id, owner.as_deref(), name)
    })
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            log_admin_failure(&headers, &e, "admin key creation failed (store error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key creation failed; no key was created",
            );
        }
        Err(e) => {
            log_admin_failure(&headers, &e, "admin key creation failed (task error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key creation failed",
            );
        }
    };
    audit(
        &state,
        &principal,
        Some(created.record.tenant_id()),
        "key.create",
        created.record.id(),
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "id": created.record.id(),
            "tenant_id": created.record.tenant_id(),
            "tenant_name": tenant.name(),
            "owner_user_id": created.record.owner_user_id(),
            "key": created.plaintext,
            "name": created.record.name(),
            "created_at": created.record.created_at(),
            "enabled": created.record.enabled(),
            "prefix": "sk-••••",
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "requests": 0,
                "estimated_requests": 0,
                "last_used_at": 0,
            },
        })),
    )
        .into_response()
}

/// 吊销 key。
pub async fn delete_key(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(key) = state.store.key(&id) else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "key not found");
    };
    if let Err(e) = authorize(&principal, Action::KeyWrite, Some(key.tenant_id())) {
        return rbac_response(e);
    }
    if principal.role == UserRole::User && key.owner_user_id() != principal.user_id.as_deref() {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "key not found");
    }
    let tenant_id = key.tenant_id().to_string();
    let bucket_key = id.clone();
    let store = state.store.clone();
    let removed = match tokio::task::spawn_blocking(move || store.delete(&id)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log_admin_failure(&headers, &e, "admin key deletion failed (store error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key deletion failed; the key is still valid",
            );
        }
        Err(e) => {
            log_admin_failure(&headers, &e, "admin key deletion failed (task error)");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key deletion failed",
            );
        }
    };
    if removed {
        audit(
            &state,
            &principal,
            Some(&tenant_id),
            "key.delete",
            &bucket_key,
        );
        if let Some(rl) = &state.rate_limiter {
            rl.evict(&bucket_key);
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        crate::openai::error_response(StatusCode::NOT_FOUND, "key not found")
    }
}

/// 列出在线 agent 明细（注册表快照，按 agent_id 排序）。
#[derive(Debug, Deserialize)]
pub struct AgentQuery {
    tenant_id: Option<String>,
}

pub async fn list_agents(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<AgentQuery>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::AgentRead, query.tenant_id.as_deref()) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(&principal, query.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let mut agents = state.registry.snapshot(state.policy.agent_stale_after);
    if let Some(tenant_id) = tenant {
        agents.retain(|a| a.tenant_id == tenant_id);
    }
    Json(agents).into_response()
}

fn audit(
    state: &AppState,
    principal: &Principal,
    tenant_id: Option<&str>,
    action: &str,
    target_id: &str,
) {
    if let Err(e) = state.store.append_audit(
        principal.user_id.as_deref(),
        principal.label(),
        tenant_id,
        action,
        target_id,
    ) {
        error!(error = %e, action, "admin audit write failed");
    }
}

fn tenant_error_response(error: TenantError) -> Response {
    let status = match error {
        TenantError::NotFound => StatusCode::NOT_FOUND,
        TenantError::NameTaken
        | TenantError::HasKeys
        | TenantError::HasUsers
        | TenantError::DefaultTenant => StatusCode::CONFLICT,
        TenantError::InvalidName | TenantError::Disabled | TenantError::BadToken => {
            StatusCode::BAD_REQUEST
        }
        TenantError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    crate::openai::error_response(status, error.to_string())
}

fn tenant_json(state: &AppState, tenant: &crate::storage::TenantRecord) -> serde_json::Value {
    let totals = state.store.tenant_totals(tenant.id());
    json!({
        "id": tenant.id(),
        "name": tenant.name(),
        "created_at": tenant.created_at(),
        "enabled": tenant.enabled(),
        "max_concurrent_requests": tenant.max_concurrent_requests(),
        "requests_per_minute": tenant.requests_per_minute(),
        "key_count": state.store.key_count_for_tenant(tenant.id()),
        "user_count": state.store.user_count_for_tenant(tenant.id()),
        "agent_count": state.registry.count_for_tenant(tenant.id()),
        "usage": {
            "prompt_tokens": totals.0,
            "completion_tokens": totals.1,
            "total_tokens": totals.2,
            "requests": totals.3,
        },
    })
}

pub async fn list_tenants(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::TenantRead, None) {
        return rbac_response(e);
    }
    let tenants = match effective_tenant(&principal, None) {
        Ok(None) => state.store.tenants(),
        Ok(Some(id)) => state.store.tenant(&id).into_iter().collect(),
        Err(e) => return rbac_response(e),
    };
    let out: Vec<_> = tenants
        .iter()
        .map(|tenant| tenant_json(&state, tenant))
        .collect();
    Json(json!(out)).into_response()
}

pub async fn tenant_by_id(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::TenantRead, Some(&id)) {
        return rbac_response(e);
    }
    let Some(tenant) = state.store.tenant(&id) else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "tenant not found");
    };
    Json(tenant_json(&state, &tenant)).into_response()
}

pub async fn create_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::TenantWrite, None) {
        return rbac_response(e);
    }
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let max = body
        .get("max_concurrent_requests")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let rpm = body
        .get("requests_per_minute")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let store = state.store.clone();
    let created =
        match tokio::task::spawn_blocking(move || store.create_tenant(name, max, rpm)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return tenant_error_response(e),
            Err(e) => {
                log_admin_failure(&headers, &e, "admin tenant creation failed (task error)");
                return crate::openai::error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tenant creation failed",
                );
            }
        };
    audit(
        &state,
        &principal,
        Some(created.record.id()),
        "tenant.create",
        created.record.id(),
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "id": created.record.id(),
            "name": created.record.name(),
            "created_at": created.record.created_at(),
            "enabled": created.record.enabled(),
            "max_concurrent_requests": created.record.max_concurrent_requests(),
            "requests_per_minute": created.record.requests_per_minute(),
            "agent_token": created.agent_token,
        })),
    )
        .into_response()
}

pub async fn update_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::TenantWrite, Some(&id)) {
        return rbac_response(e);
    }
    if state.store.tenant(&id).is_none() {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "tenant not found");
    }
    let mut patch = TenantPatch::default();
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        patch.name = Some(name.to_string());
    }
    if let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) {
        patch.enabled = Some(enabled);
    }
    if let Some(max) = body.get("max_concurrent_requests").and_then(|v| v.as_u64()) {
        patch.max_concurrent_requests = Some(max as u32);
    }
    if let Some(rpm) = body.get("requests_per_minute").and_then(|v| v.as_u64()) {
        patch.requests_per_minute = Some(rpm as u32);
    }
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.update_tenant(&id, patch)).await {
        Ok(Ok(record)) => {
            audit(
                &state,
                &principal,
                Some(record.id()),
                "tenant.update",
                record.id(),
            );
            Json(tenant_json(&state, &record)).into_response()
        }
        Ok(Err(e)) => tenant_error_response(e),
        Err(_) => {
            crate::openai::error_response(StatusCode::INTERNAL_SERVER_ERROR, "tenant update failed")
        }
    }
}

pub async fn delete_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::TenantWrite, Some(&id)) {
        return rbac_response(e);
    }
    if state.store.tenant(&id).is_none() {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "tenant not found");
    }
    if state.registry.count_for_tenant(&id) > 0 {
        return crate::openai::error_response(
            StatusCode::CONFLICT,
            "tenant still has registered agents",
        );
    }
    if state.store.user_count_for_tenant(&id) > 0 {
        return crate::openai::error_response(StatusCode::CONFLICT, "tenant still has users");
    }
    let store = state.store.clone();
    let deleted_id = id.clone();
    match tokio::task::spawn_blocking(move || store.delete_tenant(&deleted_id)).await {
        Ok(Ok(())) => {
            audit(&state, &principal, Some(&id), "tenant.delete", &id);
            state.tenant_limiter.evict(&id);
            state.tenant_rate_limiter.evict(&id);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => tenant_error_response(e),
        Err(_) => crate::openai::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "tenant deletion failed",
        ),
    }
}

pub async fn rotate_agent_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::AgentTokenRotate, Some(&id)) {
        return rbac_response(e);
    }
    if state.store.tenant(&id).is_none() {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "tenant not found");
    }
    let store = state.store.clone();
    let rotated_id = id.clone();
    match tokio::task::spawn_blocking(move || store.rotate_agent_token(&rotated_id)).await {
        Ok(Ok(token)) => {
            audit(&state, &principal, Some(&id), "agent_token.rotate", &id);
            Json(json!({ "agent_token": token })).into_response()
        }
        Ok(Err(e)) => tenant_error_response(e),
        Err(_) => crate::openai::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent token rotation failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{
        metrics::Metrics, options::Options, registry::Registry, state::AppState, storage::Storage,
    };

    fn test_state() -> AppState {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        )
    }

    /// 文件库版的 state（SL-P3-20 要造"落库真失败"）：另外给出库路径，好让测试挂触发器。
    fn super_principal() -> Extension<Principal> {
        Extension(Principal::break_glass())
    }

    fn file_backed_state() -> (AppState, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(Some(path.clone())),
            Metrics::default(),
            &opts,
        );
        (state, dir, path)
    }

    /// 用一个**独立连接**装触发器：让下一次写入必然 `RAISE(ABORT)`，从而真造出 500。
    fn install_trigger(path: &std::path::Path, sql: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    /// tracing 输出抓到内存里（该 crate 里第一处需要断言"某行日志到底有没有打"的测试）。
    ///
    /// ⚠️ 配合 `flavor = "current_thread"` 用：`set_default` 是**线程局部**的，多线程 runtime
    /// 里任务可能被调度到别的 worker 上，事件就抓不到了。
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// 规格（SL-P3-20）：admin 500 的响应体**只留固定文案**，内部错误原文进日志。
    ///
    /// 真因是造出来的：给 `api_keys` 挂一个必然 ABORT 的插入触发器 ⇒ `store.create` 真的返回
    /// `GatewayError::Sqlite("… debug: forced insert failure …")`。修好前这段原文就出现在
    /// `error.message` 里；修好后响应体只有固定文案，而原文**必须能在日志里看到** ——
    /// `admin.rs` 之前一行 log 都没有，所以"从响应体拿掉"必须同时"加进日志"，否则就是把
    /// 诊断信息从唯一的出口拿掉了。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_create_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_insert BEFORE INSERT ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced insert failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"name":"p3-20"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key creation failed; no key was created",
            "响应体必须是固定文案（语义子句留着，运维据此判断要不要重试）"
        );
        assert!(
            !message.contains("forced insert failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced insert failure"),
            "细节必须进日志（这是它唯一的出口）：{}",
            logs.text()
        );
    }

    /// 同上，吊销那一支：文案要保住"那把 key 仍然有效"这个语义（评估 §5 H2 / 记录 P1-4）。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_delete_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        let created = state.store.create("p3-20".into()).unwrap();
        let id = created.record.id().to_string();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_delete BEFORE DELETE ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced delete failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/keys/{id}"))
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key deletion failed; the key is still valid",
            "响应体必须是固定文案，且要说清那把 key 仍然有效"
        );
        assert!(
            !message.contains("forced delete failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced delete failure"),
            "细节必须进日志：{}",
            logs.text()
        );
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// 规格（P2-19）：吊销成功要把该 key 的**限流桶一并回收**——桶键就是 key id，吊销后
    /// 这个桶再也不会被取用，不丢就要留到 `ratelimit.rs` 的空闲清扫（10 分钟）为止。
    #[tokio::test]
    async fn deleting_a_key_also_drops_its_rate_limit_bucket() {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            rate_limit_per_min: 60,
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        );
        let created = state.store.create("p2-19".into()).expect("建 key 应当成功");
        let id = created.record.id().to_string();
        // 克隆一份句柄：桶表在 `Arc` 里，`delete_key` 会把 `state` 整个吃掉。
        let rl = state
            .rate_limiter
            .clone()
            .expect("前提：60/min 应当建出限流器");
        assert!(rl.try_acquire(&id), "前提：先让这个 key 建出一个桶");
        assert_eq!(rl.bucket_count(), 1);

        let resp = delete_key(State(state), super_principal(), HeaderMap::new(), Path(id)).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "吊销应当成功");

        assert_eq!(rl.bucket_count(), 0, "吊销后应立即可回收桶，不等空闲清扫");
    }

    #[tokio::test]
    async fn create_key_rejects_overlong_name() {
        let state = test_state();
        let resp = create_key(
            State(state),
            super_principal(),
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "x".repeat(65) })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // `type` 必须来自 openai::error_response 的映射表（400 → invalid_request_error），
        // 不能是本文件自造的 `invalid_request`（SDK 按 type 决定重试语义）
        assert_eq!(
            body_json(resp).await["error"]["type"],
            "invalid_request_error"
        );
    }

    /// `/admin/*` 的错误体必须与网关别处**同一个**格式：`error.type` 按状态码映射。
    ///
    /// 拆分前这里是自造的名字（`auth_error`），而 `proxy::error_response` 用的是
    /// `authentication_error`——同一个网关两种错误语义，SDK 只能按其中一种判断。
    #[tokio::test]
    async fn admin_errors_use_the_openai_error_shape() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "admin 401 同样要给 challenge（RFC 9110 §15.5.2）"
        );
        let body = body_json(resp).await;
        assert_eq!(
            body["error"]["type"], "authentication_error",
            "admin 401 的 type 与 proxy 的 401 必须一致"
        );
        assert_eq!(body["error"]["message"], "invalid admin token");
    }

    /// 规格（P3-6）：`/admin/*` 的响应必须带 `Cache-Control: no-store`。
    ///
    /// `POST /admin/keys` 的响应体里就是**一次性明文 API key**，列表/用量响应带 key 名与用量
    /// ——这些都不该被任何共享缓存留存（即便按 RFC，带凭据的请求一般不会被缓存，这仍是
    /// 显式声明）。401 那条路径也一并钉住：它是同一个 router 的响应。
    #[tokio::test]
    async fn admin_responses_are_never_stored_by_caches() {
        use tower::ServiceExt;

        for (label, auth) in [("带 token", Some("Bearer admin-token")), ("401", None)] {
            let state = test_state(); // admin_token = Some("admin-token")
            let mut req = axum::extract::Request::builder().uri("/admin/keys");
            if let Some(a) = auth {
                req = req.header(axum::http::header::AUTHORIZATION, a);
            }
            let resp = crate::http::app(state)
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{label} 的 admin 响应也必须 no-store"
            );
        }
    }

    /// 规格（P3-17）：admin 鉴权与 `/v1` 认证必须共用同一套 Bearer 解析——小写 scheme 也放行。
    #[tokio::test]
    async fn admin_auth_accepts_a_lowercase_bearer_scheme() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "`bearer` 小写应当被接受");
    }

    /// 规格（复扫 D2）：配置里 `admin_token` 带首尾空白时，**`/admin/*` 仍然可用**。
    ///
    /// 走完整路由（挂载判据 + 鉴权比较）而不只是 `AppState` 字段：入站凭据到不了带空白的那一步
    /// （`bearer_token` 与 httparse 各剪一端），所以 `"  admin-token  "` 这种值在修好前是
    /// "路由挂着、每个请求 401"，而运维看不出哪里配错了。修法是装配时剪掉两端（见 `AppState::new`），
    /// 这条判据就是"剪掉之后挂载与比较用的是同一个值"。
    #[tokio::test]
    async fn a_padded_admin_token_still_authenticates() {
        use tower::ServiceExt;

        let opts = Options {
            admin_token: Some("  admin-token  ".into()),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        );
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "带空白的 admin_token 必须被剪成 `admin-token` 而不是每个请求都 401（复扫 D2）"
        );
    }

    #[tokio::test]
    async fn create_and_list_masks_secret() {
        let state = test_state();
        let resp = create_key(
            State(state.clone()),
            super_principal(),
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "my-key" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let full_key = created["key"].as_str().unwrap().to_string();
        assert!(full_key.starts_with("sk-"));

        // 列表脱敏：含名称与固定掩码，不暴露明文，也不暴露 argon2 哈希
        let listed = list_keys(State(state), super_principal()).await;
        let text = body_json(listed).await.to_string();
        assert!(text.contains("my-key"));
        assert!(
            !text.contains(&full_key),
            "list must not leak plaintext key"
        );
        assert!(!text.contains("$argon2id$"), "list must not leak key hash");
    }
}

#[cfg(test)]
mod rbac_tests {
    use super::*;
    use crate::{
        metrics::Metrics, options::Options, rbac::AuthSource, registry::Registry, state::AppState,
        storage::hash::CheapArgon2, storage::Storage,
    };

    fn cheap() -> CheapArgon2 {
        CheapArgon2::install()
    }

    fn setup() -> (AppState, Storage, String, String, String, String) {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            ..Options::default()
        };
        let store = Storage::new(None);
        let a = store.create_tenant("alpha".into(), 0, 0).unwrap().record;
        let b = store.create_tenant("beta".into(), 0, 0).unwrap().record;
        let ta = store
            .create_user(
                "tenantadmin".into(),
                "correct horse battery".into(),
                UserRole::TenantAdmin,
                Some(a.id().to_string()),
                None,
            )
            .unwrap()
            .record;
        let user = store
            .create_user(
                "alice".into(),
                "correct horse battery".into(),
                UserRole::User,
                Some(a.id().to_string()),
                None,
            )
            .unwrap()
            .record;
        store
            .create_in(a.id(), Some(user.id()), "owned".into())
            .unwrap();
        store.create_in(b.id(), None, "other".into()).unwrap();
        let state = AppState::new_for_test(
            Registry::default(),
            store.clone(),
            Metrics::default(),
            &opts,
        );
        (
            state,
            store,
            a.id().to_string(),
            b.id().to_string(),
            ta.id().to_string(),
            user.id().to_string(),
        )
    }

    fn ext(role: UserRole, tenant: Option<&str>, id: &str) -> Extension<Principal> {
        Extension(Principal {
            user_id: Some(id.into()),
            username: "actor".into(),
            role,
            tenant_id: tenant.map(str::to_string),
            source: AuthSource::Session,
        })
    }

    async fn body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn tenant_admin_key_and_usage_are_scoped_and_foreign_filter_is_404() {
        let _cheap = cheap();
        let (state, _store, a, b, ta, _user) = setup();
        let p = ext(UserRole::TenantAdmin, Some(&a), &ta);
        let own = list_keys(State(state.clone()), p.clone()).await;
        assert_eq!(own.status(), StatusCode::OK);
        let rows = body(own).await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["tenant_id"], a);

        let foreign = list_keys_filtered(
            State(state.clone()),
            p.clone(),
            Query(TenantFilter {
                tenant_id: Some(b.clone()),
            }),
        )
        .await;
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

        let foreign_usage =
            usage_filtered(State(state), p, Query(TenantFilter { tenant_id: Some(b) })).await;
        assert_eq!(foreign_usage.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn user_sees_only_owned_keys_and_cannot_read_agents() {
        let _cheap = cheap();
        let (state, _store, a, _b, _ta, user) = setup();
        let p = ext(UserRole::User, Some(&a), &user);
        let keys = list_keys(State(state.clone()), p.clone()).await;
        assert_eq!(keys.status(), StatusCode::OK);
        let rows = body(keys).await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["owner_user_id"].as_str(), Some(user.as_str()));

        let agents = list_agents(State(state), p, Query(AgentQuery { tenant_id: None })).await;
        assert_eq!(agents.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn only_super_admin_can_write_tenants() {
        let _cheap = cheap();
        let (state, _store, a, _b, ta, _user) = setup();
        let p = ext(UserRole::TenantAdmin, Some(&a), &ta);
        let resp = create_tenant(
            State(state),
            p,
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "nope" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
