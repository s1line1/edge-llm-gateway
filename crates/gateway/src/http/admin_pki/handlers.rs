use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AppState,
};

use super::{
    dto::{pair_json, CreatePairBody, PkiQuery},
    errors::{audit, pki_error_response},
};

pub(crate) async fn status(
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

pub(crate) async fn list(
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

pub(crate) async fn create(
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

pub(crate) async fn revoke(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let Some(pki) = state.pki.as_ref() else {
        return crate::openai::error_response(StatusCode::NOT_FOUND, "PKI is not enabled");
    };
    let record = match pki.record(&id) {
        Ok(record) => record,
        Err(crate::pki::PkiError::NotFound) => {
            return pki_error_response(crate::pki::PkiError::NotFound)
        }
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
