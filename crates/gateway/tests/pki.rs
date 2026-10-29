use std::{sync::Arc, time::Duration};

use gateway::{pki::PkiConfig, storage::Storage, Gateway, GatewayConfig, Options};
use tempfile::tempdir;

fn pki_config(dir: &std::path::Path) -> PkiConfig {
    PkiConfig {
        enabled: true,
        dir: dir.join("pki"),
        server_validity_days: 30,
        client_validity_days: 7,
        require_https_for_download: false,
    }
}

fn options(keys: std::path::PathBuf) -> Options {
    Options {
        http_bind: "127.0.0.1:0".parse().unwrap(),
        quic_bind: "127.0.0.1:0".parse().unwrap(),
        admin_token: Some("dev-admin".into()),
        keys_file: Some(keys),
        session_cookie_secure: Some(false),
        ..Options::default()
    }
}

#[tokio::test]
async fn starts_with_zero_credentials_and_creates_a_pair_on_demand() {
    let dir = tempdir().unwrap();
    let keys = dir.path().join("keys.db");
    let store = Storage::with_verified(Some(keys.clone()), 16, Storage::default_verified_ttl());
    let _ = store;
    assert!(!dir.path().join("pki").exists());

    let gw = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(pki_config(dir.path())),
        opts: options(keys),
    })
    .await
    .unwrap();
    assert!(
        !dir.path().join("pki").exists(),
        "startup must not create certificates"
    );

    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();
    let status: serde_json::Value = client
        .get(format!("{base}/admin/pki/status"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["credentials"], 0);
    assert_eq!(status["waiting_for_credentials"], true);

    let created = client
        .post(format!("{base}/admin/pki/pairs"))
        .bearer_auth("dev-admin")
        .json(&serde_json::json!({
            "name": "laptop-1",
            "tenant_id": "default",
            "server_name": "gateway.example.com",
            "server_sans": ["gateway.example.com"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), reqwest::StatusCode::CREATED);
    let created: serde_json::Value = created.json().await.unwrap();
    assert_eq!(created["status"], "waiting");
    assert!(dir.path().join("pki/pairs").exists());
    assert!(!dir
        .path()
        .join("pki/pairs")
        .read_dir()
        .unwrap()
        .next()
        .is_none());

    let list: serde_json::Value = client
        .get(format!("{base}/admin/pki/pairs"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);

    let id = created["id"].as_str().unwrap();
    let download = client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), reqwest::StatusCode::OK);
    let bytes = download.bytes().await.unwrap();
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let names: Vec<String> = archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().display().to_string())
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

    let second = client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::GONE);

    gw.shutdown().await;
}

#[tokio::test]
async fn active_pairs_are_reloaded_on_restart_without_new_generation() {
    let dir = tempdir().unwrap();
    let keys = dir.path().join("keys.db");
    let cfg = pki_config(dir.path());
    let first = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(cfg.clone()),
        opts: options(keys.clone()),
    })
    .await
    .unwrap();
    let base = format!("http://{}", first.http_addr);
    let client = reqwest::Client::new();
    let created: serde_json::Value = client
        .post(format!("{base}/admin/pki/pairs"))
        .bearer_auth("dev-admin")
        .json(&serde_json::json!({
            "name": "laptop-1",
            "tenant_id": "default",
            "server_name": "gateway.example.com"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let server_cert = std::fs::read(dir.path().join(format!("pki/pairs/{id}/server.crt"))).unwrap();
    first.shutdown().await;

    let second = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(cfg),
        opts: options(keys),
    })
    .await
    .unwrap();
    let base = format!("http://{}", second.http_addr);
    let status: serde_json::Value = client
        .get(format!("{base}/admin/pki/status"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["credentials"], 1);
    assert_eq!(status["waiting_for_credentials"], false);
    assert_eq!(
        std::fs::read(dir.path().join(format!("pki/pairs/{id}/server.crt"))).unwrap(),
        server_cert,
        "restart must reuse the persisted server half"
    );
    second.shutdown().await;
}

#[allow(dead_code)]
fn _duration() -> Duration {
    Duration::from_secs(1)
}

async fn try_connect_with_bundle(
    quic_addr: std::net::SocketAddr,
    server_name: &str,
    tar_bytes: &[u8],
) -> Result<s2n_quic::Connection, String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut files = std::collections::HashMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().display().to_string();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
        files.insert(name, bytes);
    }
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_cursor = std::io::Cursor::new(&files["ca.crt"]);
    for cert in rustls_pemfile::certs(&mut ca_cursor) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut cert_cursor = std::io::Cursor::new(&files["client.crt"]);
    let certs = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_cursor = std::io::Cursor::new(&files["client.key"]);
    let key = rustls_pemfile::private_key(&mut key_cursor)
        .unwrap()
        .unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .unwrap();
    tls.alpn_protocols = vec![proto::ALPN.to_vec()];
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(tls)))
        .map_err(|e| e.to_string())?
        .with_io("0.0.0.0:0")
        .map_err(|e| e.to_string())?
        .start()
        .map_err(|e| e.to_string())?;
    let connect =
        s2n_quic::client::Connect::new(quic_addr).with_server_name(server_name.to_string());
    client.connect(connect).await.map_err(|e| e.to_string())
}

async fn connect_with_bundle(
    quic_addr: std::net::SocketAddr,
    server_name: &str,
    tar_bytes: &[u8],
) -> s2n_quic::Connection {
    try_connect_with_bundle(quic_addr, server_name, tar_bytes)
        .await
        .expect("bundle should connect")
}

#[tokio::test]
async fn downloaded_client_bundle_completes_mtls_and_marks_connected() {
    let dir = tempdir().unwrap();
    let keys = dir.path().join("keys.db");
    let gw = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(pki_config(dir.path())),
        opts: options(keys),
    })
    .await
    .unwrap();
    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();
    let created: serde_json::Value = client
        .post(format!("{base}/admin/pki/pairs"))
        .bearer_auth("dev-admin")
        .json(&serde_json::json!({
            "name": "laptop-1",
            "tenant_id": "default",
            "server_name": "gateway.example.com"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();
    let bundle = client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let _conn = connect_with_bundle(gw.quic_addr, "gateway.example.com", &bundle).await;
    let mut connected = false;
    for _ in 0..40 {
        let list: serde_json::Value = client
            .get(format!("{base}/admin/pki/pairs"))
            .bearer_auth("dev-admin")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if list[0]["status"] == "connected" {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(connected, "pair should be marked connected");
    gw.shutdown().await;
}

async fn create_pair(
    base: &str,
    client: &reqwest::Client,
    name: &str,
    server_name: &str,
) -> serde_json::Value {
    client
        .post(format!("{base}/admin/pki/pairs"))
        .bearer_auth("dev-admin")
        .json(&serde_json::json!({
            "name": name,
            "tenant_id": "default",
            "server_name": server_name
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn download(base: &str, client: &reqwest::Client, id: &str) -> Vec<u8> {
    client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn pair_a_client_cannot_validate_pair_b_and_revoke_blocks_new_handshakes() {
    let dir = tempdir().unwrap();
    let keys = dir.path().join("keys.db");
    let gw = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(pki_config(dir.path())),
        opts: options(keys),
    })
    .await
    .unwrap();
    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();
    let a = create_pair(&base, &client, "pair-a", "a.example.com").await;
    let b = create_pair(&base, &client, "pair-b", "b.example.com").await;
    let a_bundle = download(&base, &client, a["id"].as_str().unwrap()).await;
    let b_bundle = download(&base, &client, b["id"].as_str().unwrap()).await;

    let _a_conn = connect_with_bundle(gw.quic_addr, "a.example.com", &a_bundle).await;
    assert!(
        try_connect_with_bundle(gw.quic_addr, "b.example.com", &a_bundle)
            .await
            .is_err(),
        "pair A client must not validate pair B server certificate"
    );
    let _b_conn = connect_with_bundle(gw.quic_addr, "b.example.com", &b_bundle).await;

    client
        .post(format!(
            "{base}/admin/pki/pairs/{}/revoke",
            a["id"].as_str().unwrap()
        ))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap();
    assert!(
        try_connect_with_bundle(gw.quic_addr, "a.example.com", &a_bundle)
            .await
            .is_err(),
        "revoked pair must reject new handshakes"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn https_gate_blocks_plain_downloads_when_required() {
    let dir = tempdir().unwrap();
    let keys = dir.path().join("keys.db");
    let mut cfg = pki_config(dir.path());
    cfg.require_https_for_download = true;
    let gw = Gateway::start(GatewayConfig {
        tunnel: None,
        pki: Some(cfg),
        opts: options(keys),
    })
    .await
    .unwrap();
    let base = format!("http://{}", gw.http_addr);
    let client = reqwest::Client::new();
    let pair = create_pair(&base, &client, "pair-a", "a.example.com").await;
    let id = pair["id"].as_str().unwrap();
    let plain = client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), reqwest::StatusCode::CONFLICT);
    let proxied = client
        .get(format!("{base}/admin/pki/pairs/{id}/download"))
        .bearer_auth("dev-admin")
        .header("x-forwarded-proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(proxied.status(), reqwest::StatusCode::OK);
    gw.shutdown().await;
}
