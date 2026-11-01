// 测试专用：直接提供 AuthContext，不触发 /account/me 网络请求。

import type { ReactNode } from "react";

import type { User, UserRole } from "../api/types";
import { AuthContext, type AuthState } from "./AuthProvider";

export function testUser(role: UserRole = "super_admin"): User {
  return {
    id: role === "super_admin" ? "root" : role === "tenant_admin" ? "admin" : "user-1",
    username: role === "super_admin" ? "root" : role === "tenant_admin" ? "tenant-admin" : "alice",
    role,
    tenant_id: role === "super_admin" ? null : "tenant-a",
    tenant_name: role === "super_admin" ? null : "tenant-a",
    enabled: true,
    created_at: 0,
    updated_at: 0,
    last_login_at: 0,
  };
}

export function TestAuthProvider({
  children,
  role = "super_admin",
}: {
  children: ReactNode;
  role?: UserRole;
}) {
  const user = testUser(role);
  const value: AuthState = {
    user,
    source: "session",
    role,
    isLoading: false,
    isAuthenticated: true,
    refetch: () => undefined,
    login: async () => user,
    logout: async () => undefined,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
