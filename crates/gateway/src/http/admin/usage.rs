//! Per-key usage admin resource.

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use super::keys::TenantFilter;

use crate::{
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AdminRuntime,
    storage::UserRole,
};

pub async fn usage_route(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
) -> Response {
    usage_json(&state, &principal, None)
}

pub async fn usage_filtered(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<TenantFilter>,
) -> Response {
    usage_json(&state, &principal, query.tenant_id.as_deref())
}

fn usage_json(
    state: &AdminRuntime,
    principal: &Principal,
    tenant_filter: Option<&str>,
) -> Response {
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
