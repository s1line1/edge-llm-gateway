//! Namespace boundary matrix for the three Dashboard roles.

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

async fn login(client: &Client, base: &str, user: &str, password: &str) -> String {
    let resp = client
        .post(format!("{base}/auth/login"))
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login failed for {user}");
    cookie_from(&resp, "hlmg_session")
}

async fn create_user(client: &Client, base: &str, user: &str, role: &str) {
    let resp = client
        .post(format!("{base}/system/users"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({
            "username": user,
            "password": "correct horse battery",
            "role": role,
            "tenant_id": "default"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "create {role} failed");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_role_namespace_boundaries() {
    let (gw, agent, base, _seed_key) =
        start_stack(4, |o| o.admin_token = Some("admin-token".into())).await;
    let client = test_client();

    let unauth = client
        .get(format!("{base}/account/me"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    create_user(&client, &base, "plain-user", "user").await;
    create_user(&client, &base, "tenant-admin", "tenant_admin").await;
    let user = login(&client, &base, "plain-user", "correct horse battery").await;
    let admin = login(&client, &base, "tenant-admin", "correct horse battery").await;

    let user_admin = client
        .get(format!("{base}/admin/keys"))
        .header("cookie", &user)
        .send()
        .await
        .unwrap();
    assert_eq!(user_admin.status(), StatusCode::FORBIDDEN);

    let user_system = client
        .get(format!("{base}/system/tenants"))
        .header("cookie", &user)
        .send()
        .await
        .unwrap();
    assert_eq!(user_system.status(), StatusCode::FORBIDDEN);

    let admin_system = client
        .get(format!("{base}/system/tenants"))
        .header("cookie", &admin)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_system.status(), StatusCode::FORBIDDEN);

    let admin_keys = client
        .get(format!("{base}/admin/keys"))
        .header("cookie", &admin)
        .send()
        .await
        .unwrap();
    assert_eq!(admin_keys.status(), StatusCode::OK);

    let user_account = client
        .get(format!("{base}/account/keys"))
        .header("cookie", &user)
        .send()
        .await
        .unwrap();
    assert_eq!(user_account.status(), StatusCode::OK);

    let super_admin_path = client
        .get(format!("{base}/admin/keys"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(super_admin_path.status(), StatusCode::FORBIDDEN);

    let super_system = client
        .get(format!("{base}/system/tenants"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(super_system.status(), StatusCode::OK);

    agent.shutdown().await;
    gw.shutdown().await;
}
