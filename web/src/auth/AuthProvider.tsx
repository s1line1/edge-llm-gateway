// Dashboard 会话上下文：唯一的 /admin/auth/me 查询与登录/登出动作。

import { createContext, useEffect, useMemo, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "react-router-dom";

import { me, login as loginRequest, logout as logoutRequest } from "../api/auth";
import type { SessionInfo, User, UserRole } from "../api/types";

export const AUTH_QUERY_KEY = ["admin", "auth", "me"] as const;

export interface AuthState {
  user: User | null;
  source: SessionInfo["source"] | null;
  role: UserRole | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  refetch: () => void;
  login: (username: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const location = useLocation();
  const query = useQuery({
    queryKey: AUTH_QUERY_KEY,
    queryFn: me,
    // The login page intentionally has no session yet; probing /me there
    // would both add noise and race a successful login with a 401 response.
    enabled: location.pathname !== "/login",
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });

  const user = query.data?.user ?? null;
  const source = query.data?.source ?? null;

  useEffect(() => {
    const onUnauthorized = () => {
      // Keep the observer stable: removing an active query can immediately
      // recreate it and loop on a 401. A null result makes `RequireAuth`
      // redirect without re-fetching.
      queryClient.setQueryData<SessionInfo | null>(AUTH_QUERY_KEY, null);
    };
    window.addEventListener("hlmg-auth-unauthorized", onUnauthorized);
    return () => window.removeEventListener("hlmg-auth-unauthorized", onUnauthorized);
  }, [queryClient]);

  const value = useMemo<AuthState>(
    () => ({
      user,
      source,
      role: user?.role ?? null,
      isLoading: query.isPending,
      isAuthenticated: user !== null,
      refetch: () => void query.refetch(),
      login: async (username, password) => {
        const result = await loginRequest(username, password);
        queryClient.setQueryData<SessionInfo>(AUTH_QUERY_KEY, {
          user: result.user,
          csrf_token: result.csrf_token,
          source: "session",
        });
        return result.user;
      },
      logout: async () => {
        try {
          await logoutRequest();
        } finally {
          queryClient.removeQueries({ queryKey: AUTH_QUERY_KEY });
          queryClient.clear();
        }
      },
    }),
    [user, source, query, queryClient],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
