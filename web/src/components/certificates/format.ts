import type { PkiPair } from "../../api/types";

export function formatPkiTime(seconds: number | null): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString();
}

export function pkiStatusTone(status: PkiPair["status"]): "ok" | "warn" | "err" | "default" {
  if (status === "connected") return "ok";
  if (status === "waiting") return "warn";
  if (status === "revoked" || status === "expired") return "err";
  return "default";
}
