use serde::Deserialize;
use serde_json::json;

use crate::storage::PkiRecord;

#[derive(Debug, Deserialize)]
pub(crate) struct PkiQuery {
    pub(super) tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreatePairBody {
    pub(super) name: String,
    pub(super) tenant_id: Option<String>,
    pub(super) server_name: String,
    #[serde(default)]
    pub(super) server_sans: Vec<String>,
}

pub(super) fn pair_json(record: &PkiRecord, download_url: Option<String>) -> serde_json::Value {
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
