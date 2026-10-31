//! Tenant and agent-token admin resource.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AdminRuntime,
    storage::{TenantError, TenantPatch},
};

use super::shared::{audit, log_admin_failure};

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

fn tenant_json(state: &AdminRuntime, tenant: &crate::storage::TenantRecord) -> serde_json::Value {
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
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
    State(state): State<AdminRuntime>,
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
