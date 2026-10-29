//! PKI credential metadata. Private keys are files; this table is the index/state.

use super::Storage;

#[derive(Debug, Clone)]
pub struct PkiRecord {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub server_name: String,
    pub ca_fingerprint_sha256: String,
    pub server_fingerprint_sha256: String,
    pub client_fingerprint_sha256: String,
    pub serial: String,
    pub status: String,
    pub created_at: i64,
    pub created_by: String,
    pub downloaded_at: Option<i64>,
    pub last_connected_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub client_not_after: i64,
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<PkiRecord> {
    Ok(PkiRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        tenant_id: row.get(2)?,
        server_name: row.get(3)?,
        ca_fingerprint_sha256: row.get(4)?,
        server_fingerprint_sha256: row.get(5)?,
        client_fingerprint_sha256: row.get(6)?,
        serial: row.get(7)?,
        status: row.get(8)?,
        created_at: row.get(9)?,
        created_by: row.get(10)?,
        downloaded_at: row.get(11)?,
        last_connected_at: row.get(12)?,
        revoked_at: row.get(13)?,
        client_not_after: row.get(14)?,
    })
}

const SELECT: &str = "SELECT id,name,tenant_id,server_name,ca_fingerprint_sha256,\
server_fingerprint_sha256,client_fingerprint_sha256,serial,status,created_at,created_by,\
downloaded_at,last_connected_at,revoked_at,client_not_after FROM pki_credentials";

impl Storage {
    pub fn insert_pki_record(&self, record: &PkiRecord) -> Result<(), String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        conn.execute(
            "INSERT INTO pki_credentials (id,name,tenant_id,server_name,ca_fingerprint_sha256,\
             server_fingerprint_sha256,client_fingerprint_sha256,serial,status,created_at,created_by,\
             downloaded_at,last_connected_at,revoked_at,client_not_after) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            rusqlite::params![
                record.id,
                record.name,
                record.tenant_id,
                record.server_name,
                record.ca_fingerprint_sha256,
                record.server_fingerprint_sha256,
                record.client_fingerprint_sha256,
                record.serial,
                record.status,
                record.created_at,
                record.created_by,
                record.downloaded_at,
                record.last_connected_at,
                record.revoked_at,
                record.client_not_after,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn pki_record(&self, id: &str) -> Result<Option<PkiRecord>, String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        let mut stmt = conn
            .prepare(&format!("{SELECT} WHERE id = ?1"))
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([id]).map_err(|e| e.to_string())?;
        match rows.next().map_err(|e| e.to_string())? {
            Some(row) => row_to_record(row).map(Some).map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }

    /// Return all records, optionally scoped to one tenant. The table is small; filtering in
    /// Rust keeps the SQL free of optional parameters without opening an injection surface.
    pub fn pki_records(&self, tenant_id: Option<&str>) -> Result<Vec<PkiRecord>, String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        let mut stmt = conn.prepare(SELECT).map_err(|e| e.to_string())?;
        let iter = stmt
            .query_map([], row_to_record)
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in iter {
            let record = row.map_err(|e| e.to_string())?;
            if tenant_id.is_none_or(|t| t == record.tenant_id) {
                out.push(record);
            }
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        Ok(out)
    }

    pub fn mark_pki_downloaded(&self, id: &str, at: i64) -> Result<(), String> {
        self.update_pki(id, "downloaded_at", at)
    }

    pub fn mark_pki_connected(&self, id: &str, at: i64) -> Result<(), String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        conn.execute(
            "UPDATE pki_credentials SET last_connected_at=?1, status='connected' WHERE id=?2 AND status IN ('waiting','connected')",
            rusqlite::params![at, id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn revoke_pki_record(&self, id: &str, at: i64) -> Result<bool, String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        let changed = conn
            .execute(
                "UPDATE pki_credentials SET status='revoked', revoked_at=?1 WHERE id=?2 AND status != 'revoked'",
                rusqlite::params![at, id],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    pub fn delete_pki_record(&self, id: &str) -> Result<(), String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        conn.execute("DELETE FROM pki_credentials WHERE id=?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn update_pki(&self, id: &str, column: &str, at: i64) -> Result<(), String> {
        debug_assert!(column == "downloaded_at");
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "pki db lock poisoned".to_string())?;
        let Some(conn) = db.as_ref() else {
            return Err("pki requires a persistent keys_file database".into());
        };
        conn.execute(
            &format!("UPDATE pki_credentials SET {column}=?1 WHERE id=?2"),
            rusqlite::params![at, id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}
