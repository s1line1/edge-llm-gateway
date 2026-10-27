//! 多租户 e2e：租户归属、路由/模型隔离、admin CRUD 与 tenant 并发。

use super::common::*;

async fn create_tenant(client: &reqwest::Client, base: &str, name: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/admin/tenants"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    (
        body["id"].as_str().unwrap().to_string(),
        body["agent_token"].as_str().unwrap().to_string(),
    )
}

async fn create_key(client: &reqwest::Client, base: &str, name: &str, tenant_id: &str) -> String {
    let resp = client
        .post(format!("{base}/admin/keys"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({ "name": name, "tenant_id": tenant_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["key"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_tenant_agent_and_model_isolation() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw, certs, base, ..
    } = start_gateway(|o| {
        o.admin_token = Some("admin-token".into());
        o.allow_legacy_agent_registration = true;
    })
    .await;
    let client = test_client();
    let (tenant_a, token_a) = create_tenant(&client, &base, "tenant-a").await;
    let (tenant_b, token_b) = create_tenant(&client, &base, "tenant-b").await;
    let key_a = create_key(&client, &base, "key-a", &tenant_a).await;
    let key_b = create_key(&client, &base, "key-b", &tenant_b).await;

    let mock_a = start_mock_llm("mock-a").await;
    let mock_b = start_mock_llm("mock-b").await;
    let agent_a = certs.agent_for_tenant(
        &gw,
        "agent-a",
        &["model-a"],
        mock_a,
        4,
        false,
        &tenant_a,
        &token_a,
    );
    let agent_b = certs.agent_for_tenant(
        &gw,
        "agent-b",
        &["model-b"],
        mock_b,
        4,
        false,
        &tenant_b,
        &token_b,
    );
    wait_for_agents(&gw, 2, Duration::from_secs(10)).await;

    let models = client
        .get(format!("{base}/v1/models"))
        .bearer_auth(&key_b)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let ids: Vec<&str> = models["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect();
    assert!(
        ids.contains(&"model-b"),
        "B must see its own model: {ids:?}"
    );
    assert!(
        !ids.contains(&"model-a"),
        "B must not see A's model: {ids:?}"
    );

    let post = |model: &str, key: &str| {
        let client = client.clone();
        let base = base.clone();
        let model = model.to_string();
        let key = key.to_string();
        async move {
            client
                .post(format!("{base}/v1/chat/completions"))
                .bearer_auth(key)
                .json(&serde_json::json!({ "model": model, "messages": [] }))
                .send()
                .await
                .unwrap()
        }
    };

    let b_cross = post("model-a", &key_b).await;
    assert_eq!(
        b_cross.status(),
        reqwest::StatusCode::NOT_FOUND,
        "tenant B must not route to tenant A's model"
    );
    assert_eq!(post("model-b", &key_b).await.status(), 200);
    assert_eq!(post("model-a", &key_a).await.status(), 200);

    let tenants: serde_json::Value = client
        .get(format!("{base}/admin/tenants"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tenants.as_array().unwrap().len(), 3, "default + A + B");
    assert!(tenants
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["id"] == tenant_a && t["key_count"] == 1));

    let agents: serde_json::Value = client
        .get(format!("{base}/admin/agents?tenant_id={tenant_a}"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agents.as_array().unwrap().len(), 1);
    assert_eq!(agents[0]["tenant_id"], tenant_a);

    let rotated: serde_json::Value = client
        .post(format!("{base}/admin/tenants/{tenant_a}/agent-token"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rotated["agent_token"].as_str().unwrap().len(), 64);

    // admin usage 必须按 tenant 归属
    let usage: serde_json::Value = client
        .get(format!("{base}/admin/usage?tenant_id={tenant_a}"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = usage.as_array().unwrap();
    assert!(!rows.is_empty(), "tenant A usage must be recorded");
    assert!(rows.iter().all(|r| r["tenant_id"] == tenant_a));

    // 禁用 A 后 A 的 key 被 403，B 不受影响
    let resp = client
        .patch(format!("{base}/admin/tenants/{tenant_a}"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        post("model-a", &key_a).await.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(post("model-b", &key_b).await.status(), 200);

    agent_a.shutdown().await;
    agent_b.shutdown().await;
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_tenant_concurrency_is_enforced() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway {
        gw, certs, base, ..
    } = start_gateway(|o| {
        o.admin_token = Some("admin-token".into());
        o.allow_legacy_agent_registration = true;
    })
    .await;
    let client = test_client();
    let (tenant, token) = create_tenant(&client, &base, "tenant-limit").await;
    let resp = client
        .patch(format!("{base}/admin/tenants/{tenant}"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({ "max_concurrent_requests": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let key = create_key(&client, &base, "key-limit", &tenant).await;
    let mock = start_mock_llm("mock-limit").await;
    let agent = certs.agent_for_tenant(
        &gw,
        "agent-limit",
        &["mock-llm"],
        mock,
        4,
        false,
        &tenant,
        &token,
    );
    wait_for_agents(&gw, 1, Duration::from_secs(10)).await;

    let content = "x".repeat(400);
    let first = {
        let client = client.clone();
        let base = base.clone();
        let key = key.clone();
        let content = content.clone();
        tokio::spawn(async move {
            let resp = client
                .post(format!("{base}/v1/chat/completions"))
                .bearer_auth(key)
                .json(&serde_json::json!({
                    "model": "mock-llm",
                    "stream": true,
                    "messages": [{ "role": "user", "content": content }]
                }))
                .send()
                .await
                .unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        })
    };
    wait_for_any_agent_inflight(&base, 1).await;

    let second = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&key)
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "tenant concurrency must reject the second request"
    );

    let (status, body) = first.await.unwrap();
    assert_eq!(status, 200);
    assert!(body.contains("[DONE]"));
    let third = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&key)
        .json(&serde_json::json!({ "model": "mock-llm", "messages": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(third.status(), 200, "slot must be released after body end");

    agent.shutdown().await;
    gw.shutdown().await;
}

/// 规格（CON-007）：生产默认不接受 legacy `Register`；迁移开关关闭时旧 agent 不能注册。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_legacy_registration_is_rejected_when_flag_is_off() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway { gw, certs, .. } = start_gateway(|o| {
        o.admin_token = Some("admin-token".into());
        o.allow_legacy_agent_registration = false;
    })
    .await;
    let mock = start_mock_llm("legacy-off").await;
    let agent = certs.agent(&gw, "legacy", &["mock-llm"], mock, 4, false);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gw.agent_count(),
        0,
        "legacy Register must be rejected when allow_legacy_agent_registration is false"
    );
    agent.shutdown().await;
    gw.shutdown().await;
}
