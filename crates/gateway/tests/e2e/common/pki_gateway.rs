//! Production-PKI e2e fixture: dynamic pair + downloaded client bundle + real mTLS agent.

use std::io::Cursor;

use gateway::pki::PkiConfig;

use super::*;

pub struct PkiBundle {
    pub ca: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    pub server_name: String,
}

pub struct TestPkiGateway {
    pub gw: Gateway,
    pub base: String,
    pub quic_connect: SocketAddr,
    pub key: String,
    pub admin_token: String,
    pub pair_id: String,
    pub bundle: PkiBundle,
    _dir: tempfile::TempDir,
}

impl TestPkiGateway {
    pub fn admin_client(&self) -> reqwest::Client {
        test_client()
    }

    pub fn agent(
        &self,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
    ) -> Agent {
        self.agent_with_tenant(agent_id, models, upstream, max_concurrency, None, None)
    }

    pub fn agent_for_tenant(
        &self,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        tenant_id: &str,
        token: &str,
    ) -> Agent {
        self.agent_with_tenant(
            agent_id,
            models,
            upstream,
            max_concurrency,
            Some(tenant_id),
            Some(token),
        )
    }

    fn agent_with_tenant(
        &self,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        tenant_id: Option<&str>,
        token: Option<&str>,
    ) -> Agent {
        Agent::start(AgentConfig {
            cloud_addr: self.quic_connect,
            server_name: self.bundle.server_name.clone(),
            ca_cert: self.bundle.ca.clone(),
            client_cert: self.bundle.client_cert.clone(),
            client_key: self.bundle.client_key.clone_key(),
            agent_id: agent_id.into(),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            max_concurrency,
            upstream_base: format!("http://{upstream}"),
            heartbeat_interval: Duration::from_millis(200),
            request_log: false,
            tenant_id: tenant_id.map(str::to_string),
            tenant_agent_token: token.map(str::to_string),
        })
        .unwrap()
    }
}

/// Start a gateway through the production `Pki` identity, create one pair, and download its bundle.
pub async fn start_pki_gateway(tune: impl FnOnce(&mut Options)) -> TestPkiGateway {
    let dir = tempfile::tempdir().unwrap();
    let (keys_path, key) = seed_keys_db();
    let mut opts = e2e_options(Some(keys_path));
    opts.admin_token = Some("admin-token".into());
    tune(&mut opts);
    let gw = Gateway::start(GatewayConfig::pki(
        PkiConfig {
            enabled: true,
            dir: dir.path().join("pki"),
            server_validity_days: 30,
            client_validity_days: 7,
            require_https_for_download: false,
        },
        opts,
    ))
    .await
    .unwrap();

    let base = format!("http://{}", gw.http_addr);
    let client = test_client();
    let server_name = "pki-e2e.localhost";
    let created: serde_json::Value = client
        .post(format!("{base}/admin/pki/pairs"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({
            "name": "pki-e2e",
            "tenant_id": "default",
            "server_name": server_name,
            "server_sans": [server_name]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pair_id = created["id"].as_str().unwrap().to_string();
    let bytes = client
        .get(format!("{base}/admin/pki/pairs/{pair_id}/download"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut files = std::collections::HashMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().display().to_string();
        let mut data = String::new();
        std::io::Read::read_to_string(&mut entry, &mut data).unwrap();
        files.insert(path, data);
    }

    TestPkiGateway {
        quic_connect: connectable(gw.quic_addr),
        base,
        key,
        admin_token: "admin-token".into(),
        pair_id,
        bundle: PkiBundle {
            ca: parse_certs_pem(files.get("ca.crt").unwrap()),
            client_cert: parse_certs_pem(files.get("client.crt").unwrap()),
            client_key: parse_key_pem(files.get("client.key").unwrap()),
            server_name: server_name.into(),
        },
        gw,
        _dir: dir,
    }
}
