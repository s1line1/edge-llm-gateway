//! 用户管理与审计查询：所有访问都经过 `Principal` 的 tenant/role 作用域。

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{
    access::{
        rbac::{
            authorize, can_change_user_scope, can_create_user, can_manage_user, effective_tenant,
            response as rbac_response, Action, Principal,
        },
        session::{user_error_response, user_json_public},
    },
    state::AdminRuntime,
    storage::{UserPatch, UserRole},
};

#[derive(Debug, Deserialize)]
pub struct UserQuery {
    tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserBody {
    username: String,
    password: String,
    role: String,
    tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserBody {
    username: Option<String>,
    password: Option<String>,
    role: Option<String>,
    tenant_id: Option<String>,
    clear_tenant: Option<bool>,
    enabled: Option<bool>,
}

fn parse_role(raw: &str) -> Result<UserRole, ()> {
    raw.parse::<UserRole>().map_err(|_| ())
}

fn audit(
    state: &AdminRuntime,
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

fn user_not_found() -> Response {
    crate::openai::error_response(StatusCode::NOT_FOUND, "user not found")
}

pub async fn list_users(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<UserQuery>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::UserRead, query.tenant_id.as_deref()) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(&principal, query.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let users = match tenant {
        Some(tenant_id) => state.store.users_for_tenant(&tenant_id),
        None => state.store.users(),
    };
    Json(json!(users
        .iter()
        .map(|u| user_json_public(&state, u))
        .collect::<Vec<_>>()))
    .into_response()
}

pub async fn create_user(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let role = match parse_role(&body.role) {
        Ok(r) => r,
        Err(()) => return crate::openai::error_response(StatusCode::BAD_REQUEST, "invalid role"),
    };
    let tenant = match can_create_user(&principal, role, body.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    if let Err(e) = authorize(&principal, Action::UserWrite, tenant.as_deref()) {
        return rbac_response(e);
    }
    let store = state.store.clone();
    let created_by = principal.user_id.clone();
    let created = match tokio::task::spawn_blocking(move || {
        store.create_user(body.username, body.password, role, tenant, created_by)
    })
    .await
    {
        Ok(Ok(created)) => created,
        Ok(Err(e)) => return user_error_response(e),
        Err(e) => {
            error!(error = %e, "admin user creation task failed");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "user creation failed",
            );
        }
    };
    audit(
        &state,
        &principal,
        created.record.tenant_id(),
        "user.create",
        created.record.id(),
    );
    (
        StatusCode::CREATED,
        Json(user_json_public(&state, &created.record)),
    )
        .into_response()
}

pub async fn update_user(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    let Some(target) = state.store.user(&id) else {
        return user_not_found();
    };
    if let Err(e) = can_manage_user(&principal, &target, true) {
        return rbac_response(e);
    }
    if principal.user_id.as_deref() == Some(id.as_str()) && body.enabled == Some(false) {
        return crate::openai::error_response(StatusCode::BAD_REQUEST, "cannot disable yourself");
    }
    if !can_change_user_scope(&principal)
        && (body.role.is_some() || body.tenant_id.is_some() || body.clear_tenant == Some(true))
    {
        return crate::openai::error_response(StatusCode::FORBIDDEN, "permission denied");
    }
    let role = match body.role.as_deref() {
        Some(raw) => match parse_role(raw) {
            Ok(r) => Some(r),
            Err(()) => {
                return crate::openai::error_response(StatusCode::BAD_REQUEST, "invalid role")
            }
        },
        None => None,
    };
    let tenant_patch = if body.clear_tenant == Some(true) {
        Some(None)
    } else {
        body.tenant_id.map(Some)
    };
    let patch = UserPatch {
        username: body.username,
        role,
        tenant_id: tenant_patch,
        enabled: body.enabled,
        password: body.password,
    };
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.update_user(&id, patch)).await {
        Ok(Ok(updated)) => {
            audit(
                &state,
                &principal,
                updated.tenant_id(),
                "user.update",
                updated.id(),
            );
            Json(user_json_public(&state, &updated)).into_response()
        }
        Ok(Err(e)) => user_error_response(e),
        Err(e) => {
            error!(error = %e, "admin user update task failed");
            crate::openai::error_response(StatusCode::INTERNAL_SERVER_ERROR, "user update failed")
        }
    }
}

pub async fn delete_user(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    let Some(target) = state.store.user(&id) else {
        return user_not_found();
    };
    if principal.user_id.as_deref() == Some(id.as_str()) {
        return crate::openai::error_response(StatusCode::BAD_REQUEST, "cannot delete yourself");
    }
    if let Err(e) = can_manage_user(&principal, &target, true) {
        return rbac_response(e);
    }
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.delete_user(&id)).await {
        Ok(Ok(())) => {
            audit(
                &state,
                &principal,
                target.tenant_id(),
                "user.delete",
                target.id(),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => user_error_response(e),
        Err(e) => {
            error!(error = %e, "admin user deletion task failed");
            crate::openai::error_response(StatusCode::INTERNAL_SERVER_ERROR, "user deletion failed")
        }
    }
}

pub async fn list_audit(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<UserQuery>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::AuditRead, query.tenant_id.as_deref()) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(&principal, query.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let rows = state.store.audit_records(tenant.as_deref(), 100);
    Json(json!(rows
        .iter()
        .map(|r| json!({
            "id": r.id(),
            "actor_user_id": r.actor_user_id(),
            "actor_label": r.actor_label(),
            "tenant_id": r.tenant_id(),
            "action": r.action(),
            "target_id": r.target_id(),
            "created_at": r.created_at(),
        }))
        .collect::<Vec<_>>()))
    .into_response()
}
