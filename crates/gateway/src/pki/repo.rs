//! PKI metadata repository. SQL stays behind this boundary.

use crate::storage::{PkiRecord, Storage};

use super::PkiError;

#[derive(Clone)]
pub struct PkiRepository {
    store: Storage,
}

impl PkiRepository {
    pub fn new(store: Storage) -> Self {
        Self { store }
    }

    pub fn insert(&self, record: &PkiRecord) -> Result<(), PkiError> {
        self.store
            .insert_pki_record(record)
            .map_err(PkiError::Storage)
    }

    pub fn get(&self, id: &str) -> Result<Option<PkiRecord>, PkiError> {
        self.store.pki_record(id).map_err(PkiError::Storage)
    }

    pub fn list(&self, tenant_id: Option<&str>) -> Result<Vec<PkiRecord>, PkiError> {
        self.store.pki_records(tenant_id).map_err(PkiError::Storage)
    }

    pub fn mark_downloaded(&self, id: &str, at: i64) -> Result<(), PkiError> {
        self.store
            .mark_pki_downloaded(id, at)
            .map_err(PkiError::Storage)
    }

    pub fn mark_connected(&self, id: &str, at: i64) -> Result<(), PkiError> {
        self.store
            .mark_pki_connected(id, at)
            .map_err(PkiError::Storage)
    }

    pub fn revoke(&self, id: &str, at: i64) -> Result<bool, PkiError> {
        self.store
            .revoke_pki_record(id, at)
            .map_err(PkiError::Storage)
    }

    pub fn delete(&self, id: &str) -> Result<(), PkiError> {
        self.store.delete_pki_record(id).map_err(PkiError::Storage)
    }
}
