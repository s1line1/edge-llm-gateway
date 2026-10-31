//! Blocking adapter for the synchronous PKI core.
//!
//! Certificate generation, filesystem writes, tar construction, and SQLite calls must not run
//! on a Tokio worker. HTTP/admin callers use these functions; `PkiService` itself stays sync so
//! it can also be used from startup and tests.

use std::sync::Arc;

use crate::storage::PkiRecord;

use super::{DownloadBundle, PkiError, PkiService, PkiStatus};

async fn run<T, F>(service: Arc<PkiService>, operation: F) -> Result<T, PkiError>
where
    T: Send + 'static,
    F: FnOnce(&PkiService) -> Result<T, PkiError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || operation(&service))
        .await
        .map_err(|e| PkiError::Storage(format!("PKI blocking task failed: {e}")))?
}

pub(crate) async fn status(service: Arc<PkiService>) -> Result<PkiStatus, PkiError> {
    run(service, |s| s.status()).await
}

pub(crate) async fn list(
    service: Arc<PkiService>,
    tenant_id: Option<String>,
) -> Result<Vec<PkiRecord>, PkiError> {
    run(service, move |s| s.list(tenant_id.as_deref())).await
}

pub(crate) async fn record(service: Arc<PkiService>, id: String) -> Result<PkiRecord, PkiError> {
    run(service, move |s| s.record(&id)).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_pair(
    service: Arc<PkiService>,
    name: String,
    tenant_id: String,
    server_name: String,
    server_sans: Vec<String>,
    created_by: String,
    ca_common_name: String,
) -> Result<PkiRecord, PkiError> {
    run(service, move |s| {
        s.create_pair(
            &name,
            &tenant_id,
            &server_name,
            &server_sans,
            &created_by,
            &ca_common_name,
        )
    })
    .await
}

pub(crate) async fn download(
    service: Arc<PkiService>,
    id: String,
) -> Result<DownloadBundle, PkiError> {
    run(service, move |s| s.download(&id)).await
}

pub(crate) async fn revoke(service: Arc<PkiService>, id: String) -> Result<(), PkiError> {
    run(service, move |s| s.revoke(&id)).await
}
