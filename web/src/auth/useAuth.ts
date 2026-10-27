import { useContext } from "react";

import { AuthContext, type AuthState } from "./AuthProvider";

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth 需要 <AuthProvider>（只在已登录的应用壳内使用）");
  }
  return value;
}
