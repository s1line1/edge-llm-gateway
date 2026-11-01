//! 多角色 dashboard 认证 e2e：bootstrap → super → tenant admin → user。
//!
//! reqwest 未启用 cookie_store，因此这里显式从 Set-Cookie 中取出 session/csrf，再按浏览器
//! 的同一规则带回 `Cookie` 与 `X-CSRF-Token`。这样测到的是网关真实中间件，而不是测试替身。

use super::common::*;
use reqwest::{Client, Response, StatusCode};

struct Session {
    cookie: String,
    csrf: String,
}

fn cookie_from(resp: &Response, name: &str) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap_or(v).to_string())
        .unwrap_or_else(|| panic!("missing {name} cookie"))
}

async fn login(client: &Client, base: &str, user: &str, password: &str) -> Session {
    let resp = client
        .post(format!("{base}/auth/login"))
        .json(&serde_json::json!({ "username": user, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login failed for {user}");
    let cookie = cookie_from(&resp, "hlmg_session");
    let csrf = cookie_from(&resp, "hlmg_csrf")
        .split_once('=')
        .unwrap()
        .1
        .to_string();
    Session { cookie, csrf }
}

fn cookie_pair(s: &Session) -> String {
    format!("{}; hlmg_csrf={}", s.cookie, s.csrf)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn e2e_bootstrap_role_isolation_and_csrf() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let TestGateway { gw, base, .. } = start_gateway(|o| {
        o.admin_token = Some("admin-token".into());
    })
    .await;
    let client = test_client();

    // 首次启动：status 未初始化，bootstrap 只接受 admin token。
    let status: serde_json::Value = client
        .get(format!("{base}/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["bootstrapped"], false);

    let bootstrap = client
        .post(format!("{base}/auth/bootstrap"))
        .bearer_auth("admin-token")
        .json(&serde_json::json!({
            "username": "root",
            "password": "correct horse battery"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    let super_session = login(&client, &base, "root", "correct horse battery").await;

    // super 创建 tenant 与 tenant_admin。
    let tenant_resp = client
        .post(format!("{base}/system/tenants"))
        .header("cookie", cookie_pair(&super_session))
        .header("x-csrf-token", &super_session.csrf)
        .json(&serde_json::json!({ "name": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_resp.status(), StatusCode::CREATED);
    let tenant: serde_json::Value = tenant_resp.json().await.unwrap();
    let tenant_id = tenant["id"].as_str().unwrap().to_string();

    let admin_resp = client
        .post(format!("{base}/system/users"))
        .header("cookie", cookie_pair(&super_session))
        .header("x-csrf-token", &super_session.csrf)
        .json(&serde_json::json!({
            "username": "acme-admin",
            "password": "correct horse battery",
            "role": "tenant_admin",
            "tenant_id": tenant_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(admin_resp.status(), StatusCode::CREATED);

    let tenant_session = login(&client, &base, "acme-admin", "correct horse battery").await;

    // super 再建一个 tenant；tenant_admin 对它的显式过滤必须 404，列表仍只有自己的。
    let second = client
        .post(format!("{base}/system/tenants"))
        .header("cookie", cookie_pair(&super_session))
        .header("x-csrf-token", &super_session.csrf)
        .json(&serde_json::json!({ "name": "other" }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
    let second: serde_json::Value = second.json().await.unwrap();
    let other_id = second["id"].as_str().unwrap();
    for path in [
        format!("/admin/keys?tenant_id={other_id}"),
        format!("/admin/users?tenant_id={other_id}"),
        format!("/admin/usage?tenant_id={other_id}"),
    ] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("cookie", cookie_pair(&tenant_session))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let visible_tenants: serde_json::Value = client
        .get(format!("{base}/admin/tenants"))
        .header("cookie", cookie_pair(&tenant_session))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(visible_tenants.as_array().unwrap().len(), 1);

    // tenant_admin 创建普通用户。
    let user_resp = client
        .post(format!("{base}/admin/users"))
        .header("cookie", cookie_pair(&tenant_session))
        .header("x-csrf-token", &tenant_session.csrf)
        .json(&serde_json::json!({
            "username": "alice",
            "password": "correct horse battery",
            "role": "user"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(user_resp.status(), StatusCode::CREATED);

    // 普通用户登录，创建自己的 key；没有 CSRF 必须 403。
    let user_session = login(&client, &base, "alice", "correct horse battery").await;
    let me: serde_json::Value = client
        .get(format!("{base}/account/me"))
        .header("cookie", cookie_pair(&user_session))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = me["user"]["id"].as_str().unwrap().to_string();
    let no_csrf = client
        .post(format!("{base}/account/keys"))
        .header("cookie", cookie_pair(&user_session))
        .json(&serde_json::json!({ "name": "mine" }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

    let key_resp = client
        .post(format!("{base}/account/keys"))
        .header("cookie", cookie_pair(&user_session))
        .header("x-csrf-token", &user_session.csrf)
        .json(&serde_json::json!({ "name": "mine" }))
        .send()
        .await
        .unwrap();
    assert_eq!(key_resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = key_resp.json().await.unwrap();
    assert_eq!(created["owner_user_id"].as_str(), Some(user_id.as_str()));
    assert_eq!(created["tenant_id"], tenant_id);

    let keys: serde_json::Value = client
        .get(format!("{base}/account/keys"))
        .header("cookie", cookie_pair(&user_session))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(keys.as_array().unwrap().len(), 1);
    assert_eq!(keys[0]["owner_username"], "alice");

    // 普通用户不能看 agent / users。
    for path in ["/admin/agents", "/admin/users"] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("cookie", cookie_pair(&user_session))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }

    // tenant_admin 不能创建 super_admin，也不能读其他 tenant 用户。
    let escalation = client
        .post(format!("{base}/admin/users"))
        .header("cookie", cookie_pair(&tenant_session))
        .header("x-csrf-token", &tenant_session.csrf)
        .json(&serde_json::json!({
            "username": "evil",
            "password": "correct horse battery",
            "role": "super_admin"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(escalation.status(), StatusCode::FORBIDDEN);

    // break-glass admin token 仍可访问管理面。
    let break_glass = client
        .get(format!("{base}/system/keys"))
        .bearer_auth("admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(break_glass.status(), StatusCode::OK);

    // logout 撤销 session；随后 me 必须 401。
    let logout = client
        .post(format!("{base}/account/logout"))
        .header("cookie", cookie_pair(&user_session))
        .header("x-csrf-token", &user_session.csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let me = client
        .get(format!("{base}/account/me"))
        .header("cookie", cookie_pair(&user_session))
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);

    gw.shutdown().await;
}
