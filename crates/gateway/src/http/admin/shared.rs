//! Shared admin adapter helpers: failure logging and audit writes.

use axum::http::HeaderMap;
use tracing::error;

use crate::{rbac::Principal, state::AdminRuntime};

pub(super) fn log_admin_failure(headers: &HeaderMap, error: &dyn std::fmt::Display, what: &str) {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    error!(request_id, error = %error, "{what}");
}

pub(super) fn audit(
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
