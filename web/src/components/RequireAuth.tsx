// 路由守卫：等待 /account/me，未登录时重定向到 /login 并记录来源页。

import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuth } from "../auth/useAuth";
import { PageLoading } from "./PageLoading";

export default function RequireAuth() {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) return <PageLoading label="正在恢复控制台会话…" />;
  if (!user) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return <Outlet />;
}
