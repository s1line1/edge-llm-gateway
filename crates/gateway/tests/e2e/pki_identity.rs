//! Production-PKI e2e smoke: dynamic pair → downloaded bundle → real mTLS agent → HTTP.

use super::common::*;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_production_pki_pair_registers_an_agent() {
    let t = start_pki_gateway(|_| {}).await;
    let mock = start_mock_llm("pki-mock").await;
    let agent = t.agent("pki-edge", &["pki-model"], mock, 2);
    wait_for_agents(&t.gw, 1, Duration::from_secs(10)).await;

    let models = t
        .admin_client()
        .get(format!("{}/v1/models", t.base))
        .bearer_auth(&t.key)
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), reqwest::StatusCode::OK);

    let second = t
        .admin_client()
        .get(format!(
            "{}/system/pki/pairs/{}/download",
            t.base, t.pair_id
        ))
        .bearer_auth(&t.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::GONE);

    agent.shutdown().await;
    t.gw.shutdown().await;
}
