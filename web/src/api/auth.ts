// Dashboard 认证 API：session cookie、bootstrap、self password。

import { apiFetch, handle } from "./client";
import type { AuthStatus, SessionInfo, User } from "./types";

export interface LoginResult {
  user: User;
  csrf_token: string;
  expires_at: number;
}

export async function bootstrapStatus(): Promise<AuthStatus> {
  const resp = await apiFetch("/auth/status");
  return handle<AuthStatus>(resp);
}

export async function login(username: string, password: string): Promise<LoginResult> {
  const resp = await apiFetch("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  return handle<LoginResult>(resp);
}

export async function logout(): Promise<void> {
  const resp = await apiFetch("/account/logout", { method: "POST" });
  await handle<void>(resp);
}

export async function me(): Promise<SessionInfo> {
  const resp = await apiFetch("/account/me");
  return handle<SessionInfo>(resp);
}

export async function bootstrapAdmin(
  adminToken: string,
  username: string,
  password: string,
): Promise<User> {
  const resp = await apiFetch("/auth/bootstrap", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ username, password }),
  });
  return handle<User>(resp);
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const resp = await apiFetch("/account/password", {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });
  await handle<void>(resp);
}
