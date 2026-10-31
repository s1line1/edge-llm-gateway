//! API key admin resource.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AdminRuntime,
    storage::UserRole,
};

use super::shared::{audit, log_admin_failure};

/// 列出所有动态 key（不暴露明文；明文不落盘后无法显示真实前缀，用固定掩码）。
/// 每项附带该 key 的用量汇总（无记录时为 0）。
pub async fn list_keys(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
) -> Response {
    keys_json(&state, &principal, None)
}

#[derive(Debug, Deserialize)]
pub struct TenantFilter {
    pub(crate) tenant_id: Option<String>,
}

pub async fn list_keys_filtered(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<TenantFilter>,
) -> Response {
    keys_json(&state, &principal, query.tenant_id.as_deref())
}

fn keys_json(state: &AdminRuntime, principal: &Principal, tenant_filter: Option<&str>) -> Response {
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

/// 创建 key，返回明文（仅此一次展示；此后只存 argon2 哈希）。
pub async fn create_key(
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
