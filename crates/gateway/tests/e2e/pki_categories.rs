//! Production-PKI variants for the e2e categories that do not need a special transport.

use gateway::pki::PkiConfig;

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_pki_agents_category_lists_a_registered_edge() {
    let t = start_pki_gateway(|_| {}).await;
    let mock = start_mock_llm("pki-agents").await;
    let agent = t.agent("pki-agent", &["pki-model"], mock, 2);
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;

    let agents: serde_json::Value = t
        .admin_client()
        .get(format!("{}/admin/agents", t.base))
        .bearer_auth(&t.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = agents.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["agent_id"], "pki-agent");
    assert_eq!(rows[0]["tenant_id"], "default");
    assert_eq!(rows[0]["models"][0], "pki-model");

    agent.shutdown().await;
    t.gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_pki_tenants_category_registers_in_a_created_tenant() {
    let t = start_pki_gateway(|_| {}).await;
    let tenant: serde_json::Value = t
        .admin_client()
        .post(format!("{}/admin/tenants", t.base))
        .bearer_auth(&t.admin_token)
        .json(&serde_json::json!({
            "name": "pki-tenant",
            "max_concurrent_requests": 2,
            "requests_per_minute": 20
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tenant_id = tenant["id"].as_str().unwrap();
    let token = tenant["agent_token"].as_str().unwrap();
    let mock = start_mock_llm("pki-tenants").await;
    let agent = t.agent_for_tenant(
        "pki-tenant-agent",
        &["tenant-model"],
        mock,
        1,
        tenant_id,
        token,
    );
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;

    let agents: serde_json::Value = t
        .admin_client()
        .get(format!("{}/admin/agents?tenant_id={tenant_id}", t.base))
        .bearer_auth(&t.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agents.as_array().unwrap().len(), 1);
    assert_eq!(agents[0]["tenant_id"], tenant_id);

    agent.shutdown().await;
    t.gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_pki_head_timeout_category_returns_504() {
    let t = start_pki_gateway(|opts| {
        opts.head_timeout = Duration::from_secs(1);
    })
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stream);
            });
        }
    });
    let agent = t.agent("pki-stalled", &["slow-model"], stalled, 1);
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;

    let response = t
        .admin_client()
        .post(format!("{}/v1/chat/completions", t.base))
        .bearer_auth(&t.key)
        .json(&serde_json::json!({
            "model": "slow-model",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

    agent.shutdown().await;
    t.gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_pki_lifecycle_category_starts_with_zero_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let (keys_path, _key) = seed_keys_db();
    let mut opts = e2e_options(Some(keys_path));
    opts.admin_token = Some("admin-token".into());
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
    let status: serde_json::Value = test_client()
        .get(format!("{base}/admin/pki/status"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["credentials"], 0);
    assert_eq!(status["waiting_for_credentials"], true);
    assert!(!dir.path().join("pki").exists());
    gw.shutdown().await;
}
