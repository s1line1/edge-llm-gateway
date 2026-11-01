//! Role-specific account path: user login → account key → data plane.

use reqwest::{Client, Response, StatusCode};

use super::common::*;

fn cookie_from(resp: &Response, name: &str) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap_or(v).to_string())
        .unwrap_or_else(|| panic!("missing {name} cookie"))
}

async fn login(client: &Client, base: &str, user: &str, password: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/auth/login"))
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login failed for {user}");
    let session = cookie_from(&resp, "hlmg_session");
    let csrf = cookie_from(&resp, "hlmg_csrf")
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    (session, csrf)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_account_user_creates_key_and_calls_v1() {
    let (gw, agent, base, _seed_key) =
        start_stack(4, |o| o.admin_token = Some("admin-token".into())).await;
    let client = test_client();

    let created = client
        .post(format!("{base}/system/users"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({
            "username": "account-user",
            "password": "correct horse battery",
            "role": "user",
            "tenant_id": "default"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let (session, csrf) = login(&client, &base, "account-user", "correct horse battery").await;
    let made = client
        .post(format!("{base}/account/keys"))
        .header("cookie", format!("{session}; hlmg_csrf={csrf}"))
        .header("x-csrf-token", &csrf)
        .json(&serde_json::json!({ "name": "account-key" }))
        .send()
        .await
        .unwrap();
    assert_eq!(made.status(), StatusCode::CREATED);
    let made: serde_json::Value = made.json().await.unwrap();
    assert!(made["owner_user_id"].is_string());
    let key = made["key"].as_str().unwrap();

    let models = client
        .get(format!("{base}/v1/models"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), StatusCode::OK);

    agent.shutdown().await;
    gw.shutdown().await;
}
