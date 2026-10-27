// 角色路由守卫：无权访问时显示稳定的说明页，而不是空白或半截页面。

import type { ReactNode } from "react";
import { Link, Navigate, useLocation } from "react-router-dom";

import { useAuth } from "../auth/useAuth";
import type { UserRole } from "../api/types";
import { PageLoading } from "./PageLoading";

export function roleHome(role: UserRole): string {
  switch (role) {
    case "super_admin":
      return "/";
    case "tenant_admin":
      return "/tenants";
    case "user":
      return "/my-access";
  }
}

export default function RequireRole({
  roles,
  children,
}: {
  roles: UserRole[];
  children: ReactNode;
}) {
  const { user, isLoading } = useAuth();
  const location = useLocation();
  if (isLoading) return <PageLoading label="正在检查访问权限…" />;
  if (!user) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  if (!roles.includes(user.role)) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center px-5">
        <section className="panel w-full max-w-md p-7 text-center">
          <div className="eyebrow">ACCESS / DENIED</div>
          <h1 className="mt-2 text-xl font-semibold text-paper">无权访问这个页面</h1>
          <p className="mt-2 text-[11px] leading-relaxed text-mist">
            当前账号的角色是 <span className="font-mono text-cyan">{user.role}</span>。
            请回到你的工作区继续操作。
          </p>
          <Link to={roleHome(user.role)} className="btn btn-secondary mt-5 inline-flex">
            返回我的工作区
          </Link>
        </section>
      </div>
    );
  }
  return <>{children}</>;
}
