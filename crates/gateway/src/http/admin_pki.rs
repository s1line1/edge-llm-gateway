//! On-demand credential-pair admin API.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{
    pki::PkiError,
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AppState,
    storage::PkiRecord,
};

#[derive(Debug, Deserialize)]
pub struct PkiQuery {
    tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePairBody {
    name: String,
    tenant_id: Option<String>,
    server_name: String,
    #[serde(default)]
    server_sans: Vec<String>,
}

fn pki_error_response(err: PkiError) -> Response {
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

fn pair_json(record: &PkiRecord, download_url: Option<String>) -> serde_json::Value {
    json!({
        "id": record.id,
        "name": record.name,
        "tenant_id": record.tenant_id,
        "server_name": record.server_name,
        "serial": record.serial,
        "ca_fingerprint_sha256": record.ca_fingerprint_sha256,
        "server_fingerprint_sha256": record.server_fingerprint_sha256,
        "client_fingerprint_sha256": record.client_fingerprint_sha256,
        "status": record.status,
        "created_at": record.created_at,
        "created_by": record.created_by,
        "downloaded_at": record.downloaded_at,
        "last_connected_at": record.last_connected_at,
        "revoked_at": record.revoked_at,
        "client_not_after": record.client_not_after,
        "download_url": download_url,
    })
}

fn https_or_test(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

pub async fn status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::PkiRead, None) {
        return rbac_response(e);
    }
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    match pki.status() {
        Ok(status) => Json(json!({
            "enabled": status.enabled,
            "credentials": status.credentials,
            "tunnel_ready": status.tunnel_ready,
            "waiting_for_credentials": status.waiting_for_credentials,
        }))
        .into_response(),
        Err(e) => pki_error_response(e),
    }
}

pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<PkiQuery>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::PkiRead, query.tenant_id.as_deref()) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(&principal, query.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    match pki.list(tenant.as_deref()) {
        Ok(records) => Json(json!(records
            .iter()
            .map(|r| pair_json(
                r,
                if r.downloaded_at.is_none() && r.status != "revoked" {
                    Some(format!("/admin/pki/pairs/{}/download", r.id))
                } else {
                    None
                }
            ))
            .collect::<Vec<_>>()))
        .into_response(),
        Err(e) => pki_error_response(e),
    }
}

pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<CreatePairBody>,
) -> Response {
    let requested = body.tenant_id.as_deref();
    let tenant = match effective_tenant(&principal, requested) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return crate::openai::error_response(StatusCode::BAD_REQUEST, "tenant_id is required")
        }
        Err(e) => return rbac_response(e),
    };
    if let Err(e) = authorize(&principal, Action::PkiWrite, Some(&tenant)) {
        return rbac_response(e);
    }
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    let mut sans = body.server_sans;
    if !sans.iter().any(|s| s == &body.server_name) {
        sans.push(body.server_name.clone());
    }
    match pki.create_pair(
        &body.name,
        &tenant,
        &body.server_name,
        &sans,
        principal.user_id.as_deref().unwrap_or("break-glass"),
        "Home LLM Gateway CA",
    ) {
        Ok(record) => {
            audit(
                &state,
                &principal,
                Some(&tenant),
                "pki.pair.create",
                &record.id,
            );
            let url = format!("/admin/pki/pairs/{}/download", record.id);
            (StatusCode::CREATED, Json(pair_json(&record, Some(url)))).into_response()
        }
        Err(e) => pki_error_response(e),
    }
}

pub async fn download(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    let record = match pki.record(&id) {
        Ok(record) => record,
        Err(PkiError::NotFound) => return pki_error_response(PkiError::NotFound),
        Err(e) => return pki_error_response(e),
    };
    if let Err(e) = authorize(&principal, Action::PkiRead, Some(&record.tenant_id)) {
        return rbac_response(e);
    }
    if pki.config().require_https_for_download && !https_or_test(&headers) {
        return pki_error_response(PkiError::HttpsRequired);
    }
    match pki.download(&id) {
        Ok(bundle) => {
            audit(
                &state,
                &principal,
                Some(&record.tenant_id),
                "pki.pair.download",
                &id,
            );
            let mut response = bundle.bytes.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/x-tar"),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                header::HeaderValue::from_str(&format!(
                    "attachment; filename=\"{}\"",
                    bundle.filename
                ))
                .unwrap_or_else(|_| header::HeaderValue::from_static("attachment")),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            response
                .headers_mut()
                .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            response
        }
        Err(e) => pki_error_response(e),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    let record = match pki.record(&id) {
        Ok(record) => record,
        Err(PkiError::NotFound) => return pki_error_response(PkiError::NotFound),
        Err(e) => return pki_error_response(e),
    };
    if let Err(e) = authorize(&principal, Action::PkiWrite, Some(&record.tenant_id)) {
        return rbac_response(e);
    }
    match pki.revoke(&id) {
        Ok(()) => {
            audit(
                &state,
                &principal,
                Some(&record.tenant_id),
                "pki.pair.revoke",
                &id,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => pki_error_response(e),
    }
}

use axum::Extension;
