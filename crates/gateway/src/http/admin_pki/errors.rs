use axum::{http::StatusCode, response::Response};
use tracing::error;

use crate::{pki::PkiError, rbac::Principal, state::AppState};

pub(super) fn pki_error_response(err: PkiError) -> Response {
    let (status, message) = match err {
        PkiError::Invalid(msg) => (StatusCode::BAD_REQUEST, msg),
        PkiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        PkiError::NotFound => (
            StatusCode::NOT_FOUND,
            "credential pair not found".to_string(),
        ),
        PkiError::DownloadConsumed => (
            StatusCode::GONE,
            "client private key has already been downloaded; create a new pair".to_string(),
        ),
        PkiError::Expired => (
            StatusCode::GONE,
            "credential pair has expired; create a new pair".to_string(),
        ),
        PkiError::HttpsRequired => (
            StatusCode::CONFLICT,
            "client key download requires HTTPS or a loopback/SSH tunnel".to_string(),
        ),
        PkiError::Storage(msg) => {
            error!(error = %msg, "pki storage error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential storage failed".to_string(),
            )
        }
        PkiError::Io(err) => {
            error!(error = %err, "pki I/O error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential I/O failed".to_string(),
            )
        }
        PkiError::Generate(msg) => {
            error!(error = %msg, "pki generation error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential generation failed".to_string(),
            )
        }
    };
    crate::openai::error_response(status, &message)
}

pub(super) fn audit(
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
