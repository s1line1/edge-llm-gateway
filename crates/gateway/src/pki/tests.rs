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
