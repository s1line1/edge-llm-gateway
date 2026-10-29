import { QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { createQueryClient } from "./api/queryClient";
import { AuthProvider } from "./auth/AuthProvider";
import { useAuth } from "./auth/useAuth";
import Layout from "./components/Layout";
import RequireAuth from "./components/RequireAuth";
import RequireRole from "./components/RequireRole";
import { MetricsHistoryProvider } from "./hooks/useMetricsHistory";
import Agents from "./pages/Agents";
import Certificates from "./pages/Certificates";
import Keys from "./pages/Keys";
import Login from "./pages/Login";
import MetricsPage from "./pages/MetricsPage";
import MyAccess from "./pages/MyAccess";
import Overview from "./pages/Overview";
import Tenants from "./pages/Tenants";
import Users from "./pages/Users";
import "./index.css";

const queryClient = createQueryClient();

/** super_admin 需要全局 metrics；tenant_admin/user 不挂轮询，避免把跨 tenant 数据拉到浏览器。 */
function AppShell() {
  const { user } = useAuth();
  if (user?.role === "super_admin") {
    return (
      <MetricsHistoryProvider>
        <Layout />
      </MetricsHistoryProvider>
    );
  }
  return <Layout />;
}

function RoleHome() {
  const { user } = useAuth();
  if (user?.role === "super_admin") return <Overview />;
  if (user?.role === "tenant_admin") return <Navigate to="/tenants" replace />;
  return <Navigate to="/my-access" replace />;
}

function SuperOnly({ children }: { children: ReactNode }) {
  return <RequireRole roles={["super_admin"]}>{children}</RequireRole>;
}

function TenantOrSuper({ children }: { children: ReactNode }) {
  return <RequireRole roles={["super_admin", "tenant_admin"]}>{children}</RequireRole>;
}

function UserOnly({ children }: { children: ReactNode }) {
  return <RequireRole roles={["user"]}>{children}</RequireRole>;
}

createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={queryClient}>
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<RequireAuth />}>
            <Route element={<AppShell />}>
              <Route index element={<RoleHome />} />
              <Route path="/keys" element={<Keys />} />
              <Route
                path="/agents"
                element={
                  <TenantOrSuper>
                    <Agents />
                  </TenantOrSuper>
                }
              />
              <Route
                path="/tenants"
                element={
                  <TenantOrSuper>
                    <Tenants />
                  </TenantOrSuper>
                }
              />
              <Route
                path="/certificates"
                element={
                  <TenantOrSuper>
                    <Certificates />
                  </TenantOrSuper>
                }
              />
              <Route
                path="/users"
                element={
                  <TenantOrSuper>
                    <Users />
                  </TenantOrSuper>
                }
              />
              <Route
                path="/metrics"
                element={
                  <SuperOnly>
                    <MetricsPage />
                  </SuperOnly>
                }
              />
              <Route
                path="/my-access"
                element={
                  <UserOnly>
                    <MyAccess />
                  </UserOnly>
                }
              />
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  </QueryClientProvider>,
);
