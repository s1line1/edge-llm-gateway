//! 管理面授权：一个 `Principal`、一张 `Action` 矩阵、一个 tenant 作用域入口。
//!
//! 角色检查只在这里定义；handler 只调用 `authorize`/`effective_tenant`，不得各自
//! 重写角色判断。跨 tenant 的对象查找由 handler 先按作用域取数，因此不存在
//! "读出来再判断"的窗口。

use crate::storage::UserRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    Session,
    BreakGlass,
}

/// 通过管理面认证的身份。`user_id = None` 只出现在 break-glass admin token。
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Option<String>,
    pub username: String,
    pub role: UserRole,
    pub tenant_id: Option<String>,
    pub source: AuthSource,
}

impl Principal {
    pub fn break_glass() -> Self {
        Self {
            user_id: None,
            username: "admin".into(),
            role: UserRole::SuperAdmin,
            tenant_id: None,
            source: AuthSource::BreakGlass,
        }
    }

    pub fn for_user(user: &crate::storage::UserRecord) -> Self {
        Self {
            user_id: Some(user.id().to_string()),
            username: user.username().to_string(),
            role: user.role(),
            tenant_id: user.tenant_id().map(str::to_string),
            source: AuthSource::Session,
        }
    }

    pub fn is_super(&self) -> bool {
        self.role == UserRole::SuperAdmin
    }

    pub fn is_break_glass(&self) -> bool {
        self.source == AuthSource::BreakGlass
    }

    pub fn label(&self) -> &str {
        &self.username
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    TenantRead,
    TenantWrite,
    AgentTokenRotate,
    AgentRead,
    KeyRead,
    KeyWrite,
    UserRead,
    UserWrite,
    UsageRead,
    PkiRead,
    PkiWrite,
    MetricsGlobal,
    AuditRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacError {
    Forbidden,
    NotFound,
}

impl RbacError {
    pub fn status(self) -> axum::http::StatusCode {
        match self {
            Self::Forbidden => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Forbidden => "permission denied",
            Self::NotFound => "resource not found",
        }
    }
}

/// 返回该身份可访问的有效 tenant；`Ok(None)` 只可能来自 super_admin 的"全部 tenant"。
pub fn effective_tenant(
    principal: &Principal,
    requested: Option<&str>,
) -> Result<Option<String>, RbacError> {
    if principal.is_super() {
        return Ok(requested.map(str::to_string));
    }
    let own = principal.tenant_id.as_deref().ok_or(RbacError::Forbidden)?;
    match requested {
        Some(requested) if requested != own => Err(RbacError::NotFound),
        _ => Ok(Some(own.to_string())),
    }
}

/// 单个 tenant 资源的粗粒度权限；具体对象（key/user）的 owner 规则在 handler 再检查。
pub fn authorize(
    principal: &Principal,
    action: Action,
    requested_tenant: Option<&str>,
) -> Result<(), RbacError> {
    if principal.is_super() {
        return Ok(());
    }
    let own = principal.tenant_id.as_deref().ok_or(RbacError::Forbidden)?;
    if requested_tenant.is_some_and(|t| t != own) {
        return Err(RbacError::NotFound);
    }
    let allowed = match principal.role {
        UserRole::TenantAdmin => matches!(
            action,
            Action::TenantRead
                | Action::AgentTokenRotate
                | Action::AgentRead
                | Action::KeyRead
                | Action::KeyWrite
                | Action::UserRead
                | Action::UserWrite
                | Action::UsageRead
                | Action::PkiRead
                | Action::PkiWrite
        ),
        UserRole::User => matches!(
            action,
            Action::TenantRead | Action::KeyRead | Action::KeyWrite | Action::UsageRead
        ),
        UserRole::SuperAdmin => true,
    };
    if allowed {
        Ok(())
    } else {
        Err(RbacError::Forbidden)
    }
}

/// 用户管理目标：super 可管理任意用户；tenant_admin 只能管理自己 tenant 的普通用户。
/// Tenant-scoped create policy: super admin may choose any tenant; a tenant admin
/// may create only `user` in its own tenant. Returns the effective tenant.
pub fn can_create_user(
    principal: &Principal,
    role: UserRole,
    requested_tenant: Option<&str>,
) -> Result<Option<String>, RbacError> {
    if principal.is_super() {
        return Ok(requested_tenant.map(str::to_string));
    }
    if principal.role != UserRole::TenantAdmin || role != UserRole::User {
        return Err(RbacError::Forbidden);
    }
    if requested_tenant.is_some_and(|t| Some(t) != principal.tenant_id.as_deref()) {
        return Err(RbacError::NotFound);
    }
    Ok(principal.tenant_id.clone())
}

/// Only a super admin may change role or tenant scope of an existing user.
pub fn can_change_user_scope(principal: &Principal) -> bool {
    principal.is_super()
}

pub fn can_manage_user(
    principal: &Principal,
    target: &crate::storage::UserRecord,
    write: bool,
) -> Result<(), RbacError> {
    if principal.is_super() {
        return Ok(());
    }
    if principal.role != UserRole::TenantAdmin || !write {
        return Err(RbacError::Forbidden);
    }
    if target.role() != UserRole::User {
        return Err(RbacError::Forbidden);
    }
    if principal.tenant_id.as_deref() != target.tenant_id() {
        return Err(RbacError::NotFound);
    }
    Ok(())
}

pub fn response(error: RbacError) -> axum::response::Response {
    crate::openai::error_response(error.status(), error.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(role: UserRole, tenant: Option<&str>) -> Principal {
        Principal {
            user_id: Some("u1".into()),
            username: "alice".into(),
            role,
            tenant_id: tenant.map(str::to_string),
            source: AuthSource::Session,
        }
    }

    #[test]
    fn super_admin_can_do_everything_and_choose_any_tenant() {
        let p = principal(UserRole::SuperAdmin, None);
        for action in [
            Action::TenantWrite,
            Action::KeyWrite,
            Action::UserWrite,
            Action::MetricsGlobal,
            Action::AuditRead,
        ] {
            assert!(authorize(&p, action, Some("other")).is_ok());
        }
        assert_eq!(
            effective_tenant(&p, Some("other")).unwrap().as_deref(),
            Some("other")
        );
        assert_eq!(effective_tenant(&p, None).unwrap(), None);
    }

    #[test]
    fn tenant_admin_is_scoped_and_cannot_manage_platform() {
        let p = principal(UserRole::TenantAdmin, Some("a"));
        assert!(authorize(&p, Action::KeyWrite, Some("a")).is_ok());
        assert!(authorize(&p, Action::UserWrite, None).is_ok());
        assert_eq!(
            authorize(&p, Action::KeyRead, Some("b")),
            Err(RbacError::NotFound)
        );
        assert_eq!(
            authorize(&p, Action::TenantWrite, None),
            Err(RbacError::Forbidden)
        );
        assert_eq!(
            authorize(&p, Action::MetricsGlobal, None),
            Err(RbacError::Forbidden)
        );
    }

    #[test]
    fn user_can_manage_only_own_keys() {
        let p = principal(UserRole::User, Some("a"));
        assert!(authorize(&p, Action::KeyWrite, Some("a")).is_ok());
        assert!(authorize(&p, Action::UsageRead, None).is_ok());
        assert_eq!(
            authorize(&p, Action::AgentRead, None),
            Err(RbacError::Forbidden)
        );
        assert_eq!(
            authorize(&p, Action::KeyRead, Some("b")),
            Err(RbacError::NotFound)
        );
    }

    #[test]
    fn break_glass_is_super_admin() {
        let p = Principal::break_glass();
        assert!(p.is_super());
        assert!(p.is_break_glass());
        assert!(authorize(&p, Action::MetricsGlobal, None).is_ok());
    }
}
