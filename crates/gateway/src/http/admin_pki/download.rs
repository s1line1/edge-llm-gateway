use axum::{
    extract::{Extension, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    pki::PkiError,
    rbac::{authorize, response as rbac_response, Action, Principal},
    state::AppState,
};

use super::errors::{audit, pki_error_response};

fn https_or_test(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"))
}

pub(crate) async fn download(
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
