//! Dashboard 登录/会话：cookie、CSRF、bootstrap、me、logout、改密。
//!
//! 会话解析在 [`console_auth`] 中间件里完成；本模块只负责认证入口和 cookie 材料。会话 token
//! 只写入 `HttpOnly` cookie，绝不出现在 JSON；CSRF token 走独立的非 HttpOnly cookie，
//! 用于 double-submit 校验。

use axum::{
    extract::{Extension, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::{
    access::api_key::bearer_token,
    access::rbac::Principal,
    state::AdminRuntime,
    storage::hash::{constant_time_eq, lookup_of, now_secs},
    storage::{UserError, UserRecord, UserRole},
};

pub const SESSION_COOKIE: &str = "hlmg_session";
pub const CSRF_COOKIE: &str = "hlmg_csrf";
pub const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapBody {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordChangeBody {
    pub current_password: String,
    pub new_password: String,
}

/// 读取精确命名的 cookie；只做本项目用到的 ASCII token 子集。
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.trim().to_string())
    })
}

fn cookie_header(
    name: &str,
    value: &str,
    max_age: u64,
    secure: bool,
    http_only: bool,
) -> HeaderValue {
    let mut s = format!("{name}={value}; Path=/; Max-Age={max_age}; SameSite=Lax");
    if http_only {
        s.push_str("; HttpOnly");
    }
    if secure {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).expect("cookie value is hex/ASCII")
}

fn clear_cookie(name: &str, secure: bool, http_only: bool) -> HeaderValue {
    cookie_header(name, "", 0, secure, http_only)
}

/// 给响应追加 session + csrf cookie。token 必须是十六进制串（生成器保证）。
pub fn set_session_cookies(
    resp: &mut Response,
    token: &str,
    csrf: &str,
    ttl_secs: u64,
    secure: bool,
) {
    resp.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(SESSION_COOKIE, token, ttl_secs, secure, true),
    );
    resp.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(CSRF_COOKIE, csrf, ttl_secs, secure, false),
    );
}

pub fn clear_session_cookies(resp: &mut Response, secure: bool) {
    resp.headers_mut().append(
        header::SET_COOKIE,
        clear_cookie(SESSION_COOKIE, secure, true),
    );
    resp.headers_mut()
        .append(header::SET_COOKIE, clear_cookie(CSRF_COOKIE, secure, false));
}

/// CSRF double-submit：header 与 cookie 必须同时存在并常量时间相等。
pub fn csrf_matches(headers: &HeaderMap) -> bool {
    let Some(cookie) = read_cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    let Some(header) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    !cookie.is_empty()
        && !header.is_empty()
        && constant_time_eq(cookie.as_bytes(), header.as_bytes())
}

/// 有 Origin 时要求 host 与请求 Host 一致；没有 Origin 的脚本请求交给 CSRF token 校验。
pub fn origin_matches(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .split('/')
        .next()
        .unwrap_or_default();
    origin_host.eq_ignore_ascii_case(host)
}

fn is_unsafe_method(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

/// 控制面保护中间件：session 或 break-glass admin token → `Extension<Principal>`。
pub async fn console_auth(
    State(state): State<AdminRuntime>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let principal = if let Some(token) = read_cookie(req.headers(), SESSION_COOKIE) {
        match state.store.authorize_session(&token) {
            Some(user) => Principal::for_user(&user),
            None if break_glass_ok(&state, req.headers()) => Principal::break_glass(),
            None => return unauthorized("invalid or expired session"),
        }
    } else if break_glass_ok(&state, req.headers()) {
        Principal::break_glass()
    } else {
        return unauthorized("invalid admin token");
    };

    // CSRF applies to cookie sessions. A break-glass Bearer token is an explicit
    // machine credential and has no browser cookie to protect.
    if principal.source == crate::access::rbac::AuthSource::Session
        && is_unsafe_method(req.method())
        && !(csrf_matches(req.headers()) && origin_matches(req.headers()))
    {
        return crate::openai::error_response(
            StatusCode::FORBIDDEN,
            "missing or invalid CSRF token",
        );
    }

    let mut req = req;
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// Account/tenant/global namespace guard helpers.
///
/// These run inside [`console_auth`] so `Principal` is already present. A missing principal is a
/// wiring error and still returns 401; a valid principal outside the namespace returns 403.
pub async fn require_user(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    require_role(req, next, |role| role == UserRole::User).await
}

pub async fn require_tenant_admin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    require_role(req, next, |role| role == UserRole::TenantAdmin).await
}

pub async fn require_super_admin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    require_role(req, next, |role| role == UserRole::SuperAdmin).await
}

async fn require_role(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    allowed: impl FnOnce(UserRole) -> bool,
) -> Response {
    let Some(principal) = req.extensions().get::<Principal>() else {
        return unauthorized("missing authenticated principal");
    };
    if allowed(principal.role) {
        next.run(req).await
    } else {
        crate::access::rbac::response(crate::access::rbac::RbacError::Forbidden)
    }
}

fn break_glass_ok(state: &AdminRuntime, headers: &HeaderMap) -> bool {
    let Some(expected) = state.admin_token.as_deref() else {
        return false;
    };
    bearer_token(headers)
        .map(|token| constant_time_eq(expected.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

fn unauthorized(message: &str) -> Response {
    crate::openai::error_response(StatusCode::UNAUTHORIZED, message)
}

fn user_json(state: &AdminRuntime, user: &UserRecord) -> serde_json::Value {
    json!({
        "id": user.id(),
        "username": user.username(),
        "role": user.role().as_str(),
        "tenant_id": user.tenant_id(),
        "tenant_name": user.tenant_id().and_then(|id| state.store.tenant(id)).map(|t| t.name().to_string()),
        "enabled": user.enabled(),
        "created_at": user.created_at(),
        "updated_at": user.updated_at(),
        "last_login_at": user.last_login_at(),
    })
}

pub(crate) fn user_json_public(state: &AdminRuntime, user: &UserRecord) -> serde_json::Value {
    user_json(state, user)
}

pub async fn status(State(state): State<AdminRuntime>) -> Json<serde_json::Value> {
    Json(json!({
        "bootstrapped": state.store.user_count() > 0,
        "break_glass_available": state.admin_token.is_some(),
    }))
}

/// 首次启动：只有用户表为空且 Bearer admin_token 正确时才创建 super_admin。
pub async fn bootstrap(
    State(state): State<AdminRuntime>,
    headers: HeaderMap,
    Json(body): Json<BootstrapBody>,
) -> Response {
    if !break_glass_ok(&state, &headers) {
        return unauthorized("invalid admin token");
    }
    let _bootstrap_guard = state.bootstrap_lock.lock().await;
    if state.store.user_count() > 0 {
        return crate::openai::error_response(
            StatusCode::CONFLICT,
            "gateway is already bootstrapped",
        );
    }
    let store = state.store.clone();
    let username = body.username;
    let password = body.password;
    let created = match tokio::task::spawn_blocking(move || {
        store.create_user(username, password, UserRole::SuperAdmin, None, None)
    })
    .await
    {
        Ok(Ok(created)) => created,
        Ok(Err(e)) => return user_error_response(e),
        Err(e) => {
            error!(error = %e, "bootstrap task failed");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bootstrap failed",
            );
        }
    };
    let _ = state.store.append_audit(
        Some(created.record.id()),
        created.record.username(),
        None,
        "bootstrap_super_admin",
        created.record.id(),
    );
    (
        StatusCode::CREATED,
        Json(user_json(&state, &created.record)),
    )
        .into_response()
}

pub async fn login(State(state): State<AdminRuntime>, Json(body): Json<LoginBody>) -> Response {
    let username = body.username.trim().to_ascii_lowercase();
    if let Err(retry) = state.login_limiter.check(&username) {
        return rate_limited(retry);
    }
    let store = state.store.clone();
    let password = body.password;
    let lookup = username.clone();
    let result = tokio::task::spawn_blocking(move || {
        let user = store.user_by_username(&lookup);
        let ok = store.verify_password(user.as_ref(), &password);
        (user, ok)
    })
    .await;
    let (user, password_ok) = match result {
        Ok(v) => v,
        Err(e) => {
            error!(error = %e, "login verification task failed");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "login failed",
            );
        }
    };
    let Some(user) = user else {
        state.login_limiter.record_failure(&username);
        return unauthorized("invalid username or password");
    };
    if !password_ok || !user.enabled() {
        state.login_limiter.record_failure(&username);
        return unauthorized("invalid username or password");
    }
    if let Some(tenant_id) = user.tenant_id() {
        let Some(tenant) = state.store.tenant(tenant_id) else {
            state.login_limiter.record_failure(&username);
            return unauthorized("invalid username or password");
        };
        if !tenant.enabled() {
            state.login_limiter.record_failure(&username);
            return crate::openai::error_response(StatusCode::FORBIDDEN, "tenant disabled");
        }
    }

    let store = state.store.clone();
    let user_id = user.id().to_string();
    let ttl = state.session_ttl_secs;
    let session =
        match tokio::task::spawn_blocking(move || store.create_session(&user_id, ttl)).await {
            Ok(Ok(session)) => session,
            Ok(Err(e)) => return user_error_response(e),
            Err(e) => {
                error!(error = %e, "session creation task failed");
                return crate::openai::error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "login failed",
                );
            }
        };
    let store = state.store.clone();
    let uid = user.id().to_string();
    let _ = tokio::task::spawn_blocking(move || {
        store.prune_expired_sessions(now_secs());
        store.record_login(&uid);
    })
    .await;
    state.login_limiter.record_success(&username);

    let mut resp = Json(json!({
        "user": user_json(&state, &user),
        "csrf_token": session.csrf_token,
        "expires_at": session.record.expires_at(),
    }))
    .into_response();
    set_session_cookies(
        &mut resp,
        &session.token,
        &session.csrf_token,
        ttl,
        state.session_cookie_secure,
    );
    resp
}

pub async fn logout(
    State(state): State<AdminRuntime>,
    headers: HeaderMap,
    Extension(principal): Extension<Principal>,
) -> Response {
    if principal.source != crate::access::rbac::AuthSource::Session {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        clear_session_cookies(&mut resp, state.session_cookie_secure);
        return resp;
    }
    if let Some(token) = read_cookie(&headers, SESSION_COOKIE) {
        if !csrf_matches(&headers) || !origin_matches(&headers) {
            return crate::openai::error_response(
                StatusCode::FORBIDDEN,
                "missing or invalid CSRF token",
            );
        }
        state.store.revoke_session(&token);
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    clear_session_cookies(&mut resp, state.session_cookie_secure);
    resp
}

pub async fn me(
    State(state): State<AdminRuntime>,
    headers: HeaderMap,
    Extension(principal): Extension<Principal>,
) -> Response {
    let csrf = read_cookie(&headers, CSRF_COOKIE);
    if principal.is_break_glass() {
        return Json(json!({
            "user": {
                "id": null,
                "username": principal.username,
                "role": principal.role.as_str(),
                "tenant_id": null,
                "tenant_name": null,
                "enabled": true,
                "created_at": 0,
                "updated_at": 0,
                "last_login_at": 0,
            },
            "csrf_token": null,
            "source": "break_glass",
        }))
        .into_response();
    }
    let Some(user) = principal
        .user_id
        .as_deref()
        .and_then(|id| state.store.user(id))
    else {
        return unauthorized("invalid or expired session");
    };
    Json(json!({
        "user": user_json(&state, &user),
        "csrf_token": csrf,
        "source": "session",
    }))
    .into_response()
}

pub async fn change_password(
    State(state): State<AdminRuntime>,
    headers: HeaderMap,
    Extension(principal): Extension<Principal>,
    Json(body): Json<PasswordChangeBody>,
) -> Response {
    let Some(user_id) = principal.user_id.as_deref() else {
        return crate::openai::error_response(
            StatusCode::BAD_REQUEST,
            "break-glass credentials cannot change a password",
        );
    };
    let store = state.store.clone();
    let uid = user_id.to_string();
    let password = body.current_password;
    let user = match tokio::task::spawn_blocking(move || {
        let user = store.user(&uid);
        let ok = store.verify_password(user.as_ref(), &password);
        (user, ok)
    })
    .await
    {
        Ok((Some(user), true)) => user,
        Ok((Some(_), false)) => return unauthorized("current password is incorrect"),
        Ok((None, _)) => return unauthorized("invalid or expired session"),
        Err(e) => {
            error!(error = %e, "password verification task failed");
            return crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "password change failed",
            );
        }
    };
    let current_hash = read_cookie(&headers, SESSION_COOKIE).map(|t| lookup_of(&t));
    let store = state.store.clone();
    let uid = user.id().to_string();
    let new = body.new_password;
    match tokio::task::spawn_blocking(move || {
        store.set_user_password(&uid, &new, current_hash.as_deref())
    })
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => user_error_response(e),
        Err(e) => {
            error!(error = %e, "password change task failed");
            crate::openai::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "password change failed",
            )
        }
    }
}

pub(crate) fn user_error_response(error: UserError) -> Response {
    let status = match error {
        UserError::NotFound => StatusCode::NOT_FOUND,
        UserError::UsernameTaken => StatusCode::CONFLICT,
        UserError::InvalidUsername | UserError::InvalidPassword | UserError::InvalidRole => {
            StatusCode::BAD_REQUEST
        }
        UserError::TenantRequired | UserError::TenantMismatch | UserError::Disabled => {
            StatusCode::BAD_REQUEST
        }
        UserError::LastSuperAdmin => StatusCode::CONFLICT,
        UserError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    crate::openai::error_response(status, error.to_string())
}

fn rate_limited(retry_after_secs: u64) -> Response {
    let mut resp =
        crate::openai::error_response(StatusCode::TOO_MANY_REQUESTS, "too many login attempts");
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, value);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use axum::body::Body;
    use tower::ServiceExt;

    use crate::{metrics::Metrics, options::Options, registry::Registry, storage::Storage};

    fn test_app() -> axum::Router {
        let opts = Options {
            admin_token: Some("admin-token".into()),
            session_cookie_secure: Some(false),
            ..Options::default()
        };
        let state = AppState::new_for_test(
            Registry::default(),
            Storage::new(None),
            Metrics::default(),
            &opts,
        );
        crate::http::app(state)
    }

    fn post(
        path: &str,
        body: serde_json::Value,
        admin: bool,
        csrf: Option<&str>,
    ) -> axum::extract::Request {
        let mut builder = axum::extract::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if admin {
            builder = builder.header("authorization", "Bearer admin-token");
        }
        if let Some(token) = csrf {
            builder = builder.header(CSRF_HEADER, token);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn cookies(resp: &Response) -> Vec<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn bootstrap_login_me_and_csrf_gate() {
        let app = test_app();
        let status = app
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/auth/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);

        let bootstrap = app
            .clone()
            .oneshot(post(
                "/auth/bootstrap",
                json!({"username": "root", "password": "correct horse battery"}),
                true,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(bootstrap.status(), StatusCode::CREATED);

        let login = app
            .clone()
            .oneshot(post(
                "/auth/login",
                json!({"username": "root", "password": "correct horse battery"}),
                false,
                None,
            ))
            .await
            .unwrap();
        let login_status = login.status();
        let set_cookies = cookies(&login);
        let login_body_debug = axum::body::to_bytes(login.into_body(), 4096).await.unwrap();
        assert_eq!(login_status, StatusCode::OK);
        assert!(set_cookies.iter().any(|c| c.starts_with("hlmg_session=")));
        assert!(set_cookies.iter().any(|c| c.starts_with("hlmg_csrf=")));
        let login_json: serde_json::Value = serde_json::from_slice(&login_body_debug).unwrap();
        assert_eq!(login_json["user"]["role"], "super_admin");
        assert!(login_json.get("token").is_none());

        let session_cookie = set_cookies
            .iter()
            .find(|c| c.starts_with("hlmg_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = set_cookies
            .iter()
            .find(|c| c.starts_with("hlmg_csrf="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_string();

        let me = app
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .uri("/account/me")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(me.status(), StatusCode::OK);

        let cookie_pair = format!("{session_cookie}; hlmg_csrf={csrf}");
        let logout_without = app
            .clone()
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/account/logout")
                    .header(header::COOKIE, &cookie_pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_without.status(), StatusCode::FORBIDDEN);

        let logout = app
            .oneshot(
                axum::extract::Request::builder()
                    .method("POST")
                    .uri("/account/logout")
                    .header(header::COOKIE, cookie_pair)
                    .header(CSRF_HEADER, csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn cookie_parser_is_exact_named() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; hlmg_session=deadbeef; b=2"),
        );
        assert_eq!(
            read_cookie(&headers, SESSION_COOKIE).as_deref(),
            Some("deadbeef")
        );
        assert_eq!(read_cookie(&headers, "a").as_deref(), Some("1"));
        assert_eq!(read_cookie(&headers, "missing"), None);
    }

    #[test]
    fn csrf_requires_matching_cookie_and_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("hlmg_csrf=abc"));
        assert!(!csrf_matches(&headers));
        headers.insert(CSRF_HEADER, HeaderValue::from_static("abc"));
        assert!(csrf_matches(&headers));
        headers.insert(CSRF_HEADER, HeaderValue::from_static("abd"));
        assert!(!csrf_matches(&headers));
    }

    #[test]
    fn session_cookie_attributes_are_fixed() {
        let mut resp = StatusCode::OK.into_response();
        set_session_cookies(&mut resp, "aa", "bb", 60, true);
        let values: Vec<&str> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(values.iter().any(|v| v.contains("hlmg_session=aa")
            && v.contains("HttpOnly")
            && v.contains("SameSite=Lax")
            && v.contains("Secure")));
        assert!(values.iter().any(|v| v.contains("hlmg_csrf=bb")
            && !v.contains("HttpOnly")
            && v.contains("SameSite=Lax")));
    }

    #[test]
    fn origin_matches_host_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("gw.example"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://gw.example"),
        );
        assert!(origin_matches(&headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!origin_matches(&headers));
    }
}

#[cfg(test)]
mod role_guard_tests {
    use axum::{
        body::Body,
        extract::Request,
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    use super::*;
    use crate::http::test_util::principal;

    async fn probe() -> Response {
        StatusCode::NO_CONTENT.into_response()
    }

    async fn inject_role(mut req: Request, next: Next) -> Response {
        let role = match req
            .headers()
            .get("x-test-role")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
        {
            "user" => UserRole::User,
            "tenant_admin" => UserRole::TenantAdmin,
            "super_admin" => UserRole::SuperAdmin,
            _ => return StatusCode::UNAUTHORIZED.into_response(),
        };
        req.extensions_mut().insert(principal(role));
        next.run(req).await
    }

    async fn call(router: Router, role: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        if let Some(role) = role {
            req.headers_mut()
                .insert("x-test-role", role.parse().unwrap());
        }
        router.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn role_guards_require_a_principal_and_match_exact_role() {
        let user_app = Router::new()
            .route("/", get(probe))
            .route_layer(middleware::from_fn(require_user))
            .layer(middleware::from_fn(inject_role));
        assert_eq!(call(user_app.clone(), None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            call(user_app.clone(), Some("tenant_admin")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(call(user_app, Some("user")).await, StatusCode::NO_CONTENT);

        let admin_app = Router::new()
            .route("/", get(probe))
            .route_layer(middleware::from_fn(require_tenant_admin))
            .layer(middleware::from_fn(inject_role));
        assert_eq!(
            call(admin_app.clone(), None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(admin_app.clone(), Some("user")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(admin_app.clone(), Some("super_admin")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(admin_app, Some("tenant_admin")).await,
            StatusCode::NO_CONTENT
        );

        let system_app = Router::new()
            .route("/", get(probe))
            .route_layer(middleware::from_fn(require_super_admin))
            .layer(middleware::from_fn(inject_role));
        assert_eq!(
            call(system_app.clone(), None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(system_app.clone(), Some("tenant_admin")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(system_app, Some("super_admin")).await,
            StatusCode::NO_CONTENT
        );
    }
}
