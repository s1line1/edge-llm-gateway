//! Compatibility path for the split admin resource modules.

pub use crate::http::admin::*;

#[cfg(test)]
mod handler_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::{
        metrics::Metrics, options::Options, rbac::Principal, registry::Registry, state::AppState,
        storage::Storage,
    };
    use axum::{
        extract::{Extension, Path, State},
        http::{HeaderMap, StatusCode},
        response::Response,
        Json,
    };

    fn test_state() -> AppState {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        )
    }

    /// 文件库版的 state（SL-P3-20 要造"落库真失败"）：另外给出库路径，好让测试挂触发器。
    fn super_principal() -> Extension<Principal> {
        Extension(Principal::break_glass())
    }

    fn file_backed_state() -> (AppState, tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let opts = Options {
            admin_token: Some("admin-token".into()),
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(Some(path.clone())),
            Metrics::default(),
            &opts,
        );
        (state, dir, path)
    }

    /// 用一个**独立连接**装触发器：让下一次写入必然 `RAISE(ABORT)`，从而真造出 500。
    fn install_trigger(path: &std::path::Path, sql: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    /// tracing 输出抓到内存里（该 crate 里第一处需要断言"某行日志到底有没有打"的测试）。
    ///
    /// ⚠️ 配合 `flavor = "current_thread"` 用：`set_default` 是**线程局部**的，多线程 runtime
    /// 里任务可能被调度到别的 worker 上，事件就抓不到了。
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// 规格（SL-P3-20）：admin 500 的响应体**只留固定文案**，内部错误原文进日志。
    ///
    /// 真因是造出来的：给 `api_keys` 挂一个必然 ABORT 的插入触发器 ⇒ `store.create` 真的返回
    /// `GatewayError::Sqlite("… debug: forced insert failure …")`。修好前这段原文就出现在
    /// `error.message` 里；修好后响应体只有固定文案，而原文**必须能在日志里看到** ——
    /// `admin.rs` 之前一行 log 都没有，所以"从响应体拿掉"必须同时"加进日志"，否则就是把
    /// 诊断信息从唯一的出口拿掉了。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_create_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_insert BEFORE INSERT ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced insert failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"name":"p3-20"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key creation failed; no key was created",
            "响应体必须是固定文案（语义子句留着，运维据此判断要不要重试）"
        );
        assert!(
            !message.contains("forced insert failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced insert failure"),
            "细节必须进日志（这是它唯一的出口）：{}",
            logs.text()
        );
    }

    /// 同上，吊销那一支：文案要保住"那把 key 仍然有效"这个语义（评估 §5 H2 / 记录 P1-4）。
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_delete_keeps_internals_out_of_the_body_and_in_the_log() {
        use tower::ServiceExt;

        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (state, _dir, path) = file_backed_state();
        let created = state.store.create("p3-20".into()).unwrap();
        let id = created.record.id().to_string();
        install_trigger(
            &path,
            "CREATE TRIGGER dbg_fail_delete BEFORE DELETE ON api_keys
             BEGIN SELECT RAISE(ABORT, 'debug: forced delete failure'); END;",
        );

        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .method("DELETE")
                    .uri(format!("/admin/keys/{id}"))
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        let message = body["error"]["message"].as_str().unwrap();
        assert_eq!(
            message, "key deletion failed; the key is still valid",
            "响应体必须是固定文案，且要说清那把 key 仍然有效"
        );
        assert!(
            !message.contains("forced delete failure") && !message.contains("SQLite"),
            "内部错误原文/类别不得出现在响应体：{message}"
        );
        assert!(
            logs.text().contains("debug: forced delete failure"),
            "细节必须进日志：{}",
            logs.text()
        );
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// 规格（P2-19）：吊销成功要把该 key 的**限流桶一并回收**——桶键就是 key id，吊销后
    /// 这个桶再也不会被取用，不丢就要留到 `ratelimit.rs` 的空闲清扫（10 分钟）为止。
    #[tokio::test]
    async fn deleting_a_key_also_drops_its_rate_limit_bucket() {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            rate_limit_per_min: 60,
            head_timeout: Duration::from_secs(5),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        );
        let created = state.store.create("p2-19".into()).expect("建 key 应当成功");
        let id = created.record.id().to_string();
        // 克隆一份句柄：桶表在 `Arc` 里，`delete_key` 会把 `state` 整个吃掉。
        let rl = state
            .rate_limiter
            .clone()
            .expect("前提：60/min 应当建出限流器");
        assert!(rl.try_acquire(&id), "前提：先让这个 key 建出一个桶");
        assert_eq!(rl.bucket_count(), 1);

        let resp = delete_key(
            State(state.admin().clone()),
            super_principal(),
            HeaderMap::new(),
            Path(id),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "吊销应当成功");

        assert_eq!(rl.bucket_count(), 0, "吊销后应立即可回收桶，不等空闲清扫");
    }

    #[tokio::test]
    async fn create_key_rejects_overlong_name() {
        let state = test_state();
        let resp = create_key(
            State(state.admin().clone()),
            super_principal(),
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "x".repeat(65) })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // `type` 必须来自 openai::error_response 的映射表（400 → invalid_request_error），
        // 不能是本文件自造的 `invalid_request`（SDK 按 type 决定重试语义）
        assert_eq!(
            body_json(resp).await["error"]["type"],
            "invalid_request_error"
        );
    }

    /// `/admin/*` 的错误体必须与网关别处**同一个**格式：`error.type` 按状态码映射。
    ///
    /// 拆分前这里是自造的名字（`auth_error`），而 `proxy::error_response` 用的是
    /// `authentication_error`——同一个网关两种错误语义，SDK 只能按其中一种判断。
    #[tokio::test]
    async fn admin_errors_use_the_openai_error_shape() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "admin 401 同样要给 challenge（RFC 9110 §15.5.2）"
        );
        let body = body_json(resp).await;
        assert_eq!(
            body["error"]["type"], "authentication_error",
            "admin 401 的 type 与 proxy 的 401 必须一致"
        );
        assert_eq!(body["error"]["message"], "invalid admin token");
    }

    /// 规格（P3-6）：`/admin/*` 的响应必须带 `Cache-Control: no-store`。
    ///
    /// `POST /admin/keys` 的响应体里就是**一次性明文 API key**，列表/用量响应带 key 名与用量
    /// ——这些都不该被任何共享缓存留存（即便按 RFC，带凭据的请求一般不会被缓存，这仍是
    /// 显式声明）。401 那条路径也一并钉住：它是同一个 router 的响应。
    #[tokio::test]
    async fn admin_responses_are_never_stored_by_caches() {
        use tower::ServiceExt;

        for (label, auth) in [("带 token", Some("Bearer admin-token")), ("401", None)] {
            let state = test_state(); // admin_token = Some("admin-token")
            let mut req = axum::extract::Request::builder().uri("/admin/keys");
            if let Some(a) = auth {
                req = req.header(axum::http::header::AUTHORIZATION, a);
            }
            let resp = crate::http::app(state)
                .oneshot(req.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{label} 的 admin 响应也必须 no-store"
            );
        }
    }

    /// 规格（P3-17）：admin 鉴权与 `/v1` 认证必须共用同一套 Bearer 解析——小写 scheme 也放行。
    #[tokio::test]
    async fn admin_auth_accepts_a_lowercase_bearer_scheme() {
        use tower::ServiceExt;

        let state = test_state(); // admin_token = Some("admin-token")
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "`bearer` 小写应当被接受");
    }

    /// 规格（复扫 D2）：配置里 `admin_token` 带首尾空白时，**`/admin/*` 仍然可用**。
    ///
    /// 走完整路由（挂载判据 + 鉴权比较）而不只是 `AppState` 字段：入站凭据到不了带空白的那一步
    /// （`bearer_token` 与 httparse 各剪一端），所以 `"  admin-token  "` 这种值在修好前是
    /// "路由挂着、每个请求 401"，而运维看不出哪里配错了。修法是装配时剪掉两端（见 `AppState::new`），
    /// 这条判据就是"剪掉之后挂载与比较用的是同一个值"。
    #[tokio::test]
    async fn a_padded_admin_token_still_authenticates() {
        use tower::ServiceExt;

        let opts = Options {
            admin_token: Some("  admin-token  ".into()),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        );
        let resp = crate::http::app(state)
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/admin/keys")
                    .header(axum::http::header::AUTHORIZATION, "Bearer admin-token")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "带空白的 admin_token 必须被剪成 `admin-token` 而不是每个请求都 401（复扫 D2）"
        );
    }

    #[tokio::test]
    async fn create_and_list_masks_secret() {
        let state = test_state();
        let resp = create_key(
            State(state.clone().admin().clone()),
            super_principal(),
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "my-key" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let full_key = created["key"].as_str().unwrap().to_string();
        assert!(full_key.starts_with("sk-"));

        // 列表脱敏：含名称与固定掩码，不暴露明文，也不暴露 argon2 哈希
        let listed = list_keys(State(state.admin().clone()), super_principal()).await;
        let text = body_json(listed).await.to_string();
        assert!(text.contains("my-key"));
        assert!(
            !text.contains(&full_key),
            "list must not leak plaintext key"
        );
        assert!(!text.contains("$argon2id$"), "list must not leak key hash");
    }
}

#[cfg(test)]
mod rbac_tests {
    use super::*;
    use crate::{
        metrics::Metrics,
        options::Options,
        rbac::{AuthSource, Principal},
        registry::Registry,
        state::AppState,
        storage::hash::CheapArgon2,
        storage::Storage,
        storage::UserRole,
    };
    use axum::{
        extract::{Extension, Query, State},
        http::{HeaderMap, StatusCode},
        response::Response,
        Json,
    };

    fn cheap() -> CheapArgon2 {
        CheapArgon2::install()
    }

    fn setup() -> (AppState, Storage, String, String, String, String) {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            ..Options::default()
        };
        let store = Storage::new(None);
        let a = store.create_tenant("alpha".into(), 0, 0).unwrap().record;
        let b = store.create_tenant("beta".into(), 0, 0).unwrap().record;
        let ta = store
            .create_user(
                "tenantadmin".into(),
                "correct horse battery".into(),
                UserRole::TenantAdmin,
                Some(a.id().to_string()),
                None,
            )
            .unwrap()
            .record;
        let user = store
            .create_user(
                "alice".into(),
                "correct horse battery".into(),
                UserRole::User,
                Some(a.id().to_string()),
                None,
            )
            .unwrap()
            .record;
        store
            .create_in(a.id(), Some(user.id()), "owned".into())
            .unwrap();
        store.create_in(b.id(), None, "other".into()).unwrap();
        let state = AppState::new_for_test(
            Registry::default(),
            store.clone(),
            Metrics::default(),
            &opts,
        );
        (
            state,
            store,
            a.id().to_string(),
            b.id().to_string(),
            ta.id().to_string(),
            user.id().to_string(),
        )
    }

    fn ext(role: UserRole, tenant: Option<&str>, id: &str) -> Extension<Principal> {
        Extension(Principal {
            user_id: Some(id.into()),
            username: "actor".into(),
            role,
            tenant_id: tenant.map(str::to_string),
            source: AuthSource::Session,
        })
    }

    async fn body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn tenant_admin_key_and_usage_are_scoped_and_foreign_filter_is_404() {
        let _cheap = cheap();
        let (state, _store, a, b, ta, _user) = setup();
        let p = ext(UserRole::TenantAdmin, Some(&a), &ta);
        let own = list_keys(State(state.clone().admin().clone()), p.clone()).await;
        assert_eq!(own.status(), StatusCode::OK);
        let rows = body(own).await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["tenant_id"], a);

        let foreign = list_keys_filtered(
            State(state.clone().admin().clone()),
            p.clone(),
            Query(TenantFilter {
                tenant_id: Some(b.clone()),
            }),
        )
        .await;
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

        let foreign_usage = usage_filtered(
            State(state.admin().clone()),
            p,
            Query(TenantFilter { tenant_id: Some(b) }),
        )
        .await;
        assert_eq!(foreign_usage.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn user_sees_only_owned_keys_and_cannot_read_agents() {
        let _cheap = cheap();
        let (state, _store, a, _b, _ta, user) = setup();
        let p = ext(UserRole::User, Some(&a), &user);
        let keys = list_keys(State(state.clone().admin().clone()), p.clone()).await;
        assert_eq!(keys.status(), StatusCode::OK);
        let rows = body(keys).await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["owner_user_id"].as_str(), Some(user.as_str()));

        let agents = list_agents(
            State(state.admin().clone()),
            p,
            Query(AgentQuery { tenant_id: None }),
        )
        .await;
        assert_eq!(agents.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn only_super_admin_can_write_tenants() {
        let _cheap = cheap();
        let (state, _store, a, _b, ta, _user) = setup();
        let p = ext(UserRole::TenantAdmin, Some(&a), &ta);
        let resp = create_tenant(
            State(state.admin().clone()),
            p,
            HeaderMap::new(),
            Json(serde_json::json!({ "name": "nope" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
