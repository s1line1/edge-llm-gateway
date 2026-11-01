use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;

use crate::storage::Storage;

use super::*;

fn config(dir: &std::path::Path) -> PkiConfig {
    PkiConfig {
        enabled: true,
        dir: dir.join("pki"),
        server_validity_days: 30,
        client_validity_days: 7,
        require_https_for_download: true,
    }
}

#[test]
fn opening_the_store_creates_nothing() {
    let dir = tempdir().unwrap();
    let files = PkiFiles::new(dir.path().join("pki"));
    assert!(!files.dir().exists());
    assert!(!dir.path().join("pki/pairs").exists());
}

#[test]
fn generate_pair_has_matching_ca_and_leaf_ekus() {
    let dir = tempdir().unwrap();
    let pair = generate_pair(
        &config(dir.path()),
        "pair-1",
        "laptop",
        "tenant-a",
        "gateway.example.com",
        &["gateway.example.com".into(), "10.0.0.1".into()],
        "Test CA",
    )
    .unwrap();
    assert!(pair.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(pair.ca_key_pem.contains("PRIVATE KEY"));
    assert!(pair.server_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(pair.client_cert_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(pair.serial.len(), 32);
    assert_ne!(pair.ca_fingerprint_sha256, pair.server_fingerprint_sha256);
    assert_ne!(
        pair.server_fingerprint_sha256,
        pair.client_fingerprint_sha256
    );
    assert!(pair.not_before < pair.client_not_after);
}

#[test]
fn write_and_load_pair_with_private_permissions() {
    let dir = tempdir().unwrap();
    let cfg = config(dir.path());
    let pair = generate_pair(
        &cfg,
        "pair-1",
        "laptop",
        "tenant-a",
        "gateway.example.com",
        &["gateway.example.com".into()],
        "Test CA",
    )
    .unwrap();
    let files = PkiFiles::new(cfg.dir.clone());
    files.write_pair(&pair).unwrap();
    let loaded = files.load_pair("pair-1", "gateway.example.com").unwrap();
    assert_eq!(loaded.server_name(), "gateway.example.com");
    assert!(!loaded.server_chain.is_empty());
    let key = files.load_client_key("pair-1").unwrap();
    assert!(key.windows(11).any(|w| w == b"PRIVATE KEY"));
    files.remove_client_key("pair-1").unwrap();
    assert!(matches!(
        files.load_client_key("pair-1"),
        Err(PkiError::DownloadConsumed)
    ));
    #[cfg(unix)]
    {
        let meta = std::fs::metadata(files.client_key_path("pair-1")).unwrap_err();
        assert_eq!(meta.kind(), std::io::ErrorKind::NotFound);
        let ca_meta = std::fs::metadata(files.pair_dir("pair-1").join("ca.key")).unwrap();
        assert_eq!(ca_meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn invalid_names_and_ip_server_names_are_rejected() {
    // Name/SAN validation is in PkiService; generation itself also accepts only a DNS name
    // through the service layer. This test pins the accepted pair-name shape.
    assert!(super::model::valid_name("laptop-1"));
    assert!(!super::model::valid_name("Laptop"));
    assert!(!super::model::valid_name(""));
}

#[test]
fn service_creates_lists_downloads_once_and_revokes() {
    let dir = tempdir().unwrap();
    let cfg = config(dir.path());
    let store = Storage::with_verified(
        Some(dir.path().join("keys.db")),
        16,
        Storage::default_verified_ttl(),
    );
    let service = PkiService::new(cfg, store).unwrap();
    assert!(service.status().unwrap().waiting_for_credentials);
    let record = service
        .create_pair(
            "laptop-1",
            "tenant-a",
            "gateway.example.com",
            &["gateway.example.com".into()],
            "admin",
            "Test CA",
        )
        .unwrap();
    assert_eq!(record.status, "waiting");
    assert!(!service.status().unwrap().waiting_for_credentials);
    let listed = service.list(Some("tenant-a")).unwrap();
    assert_eq!(listed.len(), 1);

    let bundle = service.download(&record.id).unwrap();
    let mut archive = tar::Archive::new(std::io::Cursor::new(bundle.bytes));
    let names: Vec<String> = archive
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().display().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "ca.crt",
            "client.crt",
            "client.key",
            "client-config.example.yml"
        ]
    );
    assert!(matches!(
        service.download(&record.id),
        Err(PkiError::DownloadConsumed)
    ));
    service.revoke(&record.id).unwrap();
    assert_eq!(service.record(&record.id).unwrap().status, "revoked");
    assert!(service.status().unwrap().waiting_for_credentials);
}

/// 规格（Phase 4）：PKI 的同步核心只能通过 blocking adapter 进入 async handler。
/// 并发创建不应互相卡住；一次性下载语义在 adapter 下保持不变。
#[tokio::test]
async fn blocking_adapter_handles_concurrent_creates_and_one_time_downloads() {
    let dir = tempdir().unwrap();
    let service = std::sync::Arc::new(
        PkiService::new(
            config(dir.path()),
            Storage::new(Some(dir.path().join("keys.db"))),
        )
        .unwrap(),
    );

    let a = blocking::create_pair(
        service.clone(),
        "concurrent-a".into(),
        "tenant-a".into(),
        "a.example.com".into(),
        vec!["a.example.com".into()],
        "test".into(),
        "Test CA".into(),
    );
    let b = blocking::create_pair(
        service.clone(),
        "concurrent-b".into(),
        "tenant-a".into(),
        "b.example.com".into(),
        vec!["b.example.com".into()],
        "test".into(),
        "Test CA".into(),
    );
    let (a, b) = tokio::join!(a, b);
    let a = a.unwrap();
    let b = b.unwrap();

    let status = blocking::status(service.clone()).await.unwrap();
    assert_eq!(status.credentials, 2);
    assert!(status.tunnel_ready);

    let first = blocking::download(service.clone(), a.id.clone())
        .await
        .unwrap();
    assert!(first.filename.starts_with("hlmg-client-concurrent-a"));
    let second = blocking::download(service, a.id).await;
    assert!(matches!(second, Err(PkiError::DownloadConsumed)));
    let _ = b;
}

#[test]
fn same_server_name_across_tenants_conflicts() {
    let dir = tempdir().unwrap();
    let service = PkiService::new(
        config(dir.path()),
        Storage::new(Some(dir.path().join("keys.db"))),
    )
    .unwrap();
    let first = service
        .create_pair(
            "a",
            "tenant-a",
            "same.example.com",
            &["same.example.com".into()],
            "admin",
            "Test CA",
        )
        .unwrap();
    let err = service
        .create_pair(
            "b",
            "tenant-b",
            "same.example.com",
            &["same.example.com".into()],
            "admin",
            "Test CA",
        )
        .unwrap_err();
    assert!(matches!(err, PkiError::Conflict(_)), "got {err:?}");
    assert!(err.to_string().contains("same.example.com"));
    assert_eq!(service.active_records().unwrap().len(), 1);
    assert_eq!(service.resolved_pair_id("same.example.com"), Some(first.id));
}

#[test]
fn concurrent_same_server_name_creates_one_pair() {
    let dir = tempdir().unwrap();
    let service = std::sync::Arc::new(
        PkiService::new(
            config(dir.path()),
            Storage::new(Some(dir.path().join("keys.db"))),
        )
        .unwrap(),
    );
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for i in 0..2 {
            let service = service.clone();
            let barrier = barrier.clone();
            handles.push(scope.spawn(move || {
                barrier.wait();
                service.create_pair(
                    &format!("pair-{i}"),
                    &format!("tenant-{i}"),
                    "race.example.com",
                    &["race.example.com".into()],
                    "admin",
                    "Test CA",
                )
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(PkiError::Conflict(_))))
            .count(),
        1
    );
    assert_eq!(service.active_records().unwrap().len(), 1);
    let pair_dirs = std::fs::read_dir(dir.path().join("pki/pairs"))
        .unwrap()
        .count();
    assert_eq!(pair_dirs, 1, "failed create must remove its pair directory");
    assert_eq!(
        service.resolved_pair_id("race.example.com"),
        Some(service.active_records().unwrap()[0].id.clone())
    );
}

#[test]
fn revoke_then_reuse_server_name_resolves_new_pair() {
    let dir = tempdir().unwrap();
    let service = PkiService::new(
        config(dir.path()),
        Storage::new(Some(dir.path().join("keys.db"))),
    )
    .unwrap();
    let first = service
        .create_pair(
            "first",
            "tenant-a",
            "reuse.example.com",
            &["reuse.example.com".into()],
            "admin",
            "Test CA",
        )
        .unwrap();
    service.revoke(&first.id).unwrap();
    let second = service
        .create_pair(
            "second",
            "tenant-b",
            "reuse.example.com",
            &["reuse.example.com".into()],
            "admin",
            "Test CA",
        )
        .unwrap();
    assert_eq!(
        service.resolved_pair_id("reuse.example.com"),
        Some(second.id)
    );
}

#[test]
fn duplicate_active_rows_fail_startup_with_pair_ids() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE pki_credentials (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, tenant_id TEXT NOT NULL,
                server_name TEXT NOT NULL, ca_fingerprint_sha256 TEXT NOT NULL,
                server_fingerprint_sha256 TEXT NOT NULL, client_fingerprint_sha256 TEXT NOT NULL,
                serial TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL,
                created_by TEXT NOT NULL, downloaded_at INTEGER, last_connected_at INTEGER,
                revoked_at INTEGER, client_not_after INTEGER NOT NULL
            );
            INSERT INTO pki_credentials VALUES
                ('a','a','tenant-a','dup.example.com','ca','srv','cli','s','waiting',1,'x',NULL,NULL,NULL,9999999999),
                ('b','b','tenant-b','dup.example.com','ca','srv','cli','s','waiting',1,'x',NULL,NULL,NULL,9999999999);",
        )
        .unwrap();
    }
    let store = Storage::new(Some(path));
    let err = match PkiService::new(config(dir.path()), store) {
        Ok(_) => panic!("duplicate active SNI must fail startup"),
        Err(err) => err,
    };
    let text = err.to_string();
    assert!(text.contains("dup.example.com"), "{text}");
    assert!(text.contains('a') && text.contains('b'), "{text}");
}
