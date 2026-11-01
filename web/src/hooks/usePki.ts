import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type ApiScope,
  createPkiPair,
  downloadPkiPair,
  fetchPkiStatus,
  listPkiPairs,
  listTenants,
  revokePkiPair,
} from "../api/client";
import type { CreatePkiPairBody, PkiPair } from "../api/types";

export function usePki(scope: ApiScope, isSuper: boolean, userTenantId: string | null) {
  const queryClient = useQueryClient();
  const statusQuery = useQuery({
    queryKey: ["admin", "pki", "status", scope],
    queryFn: () => fetchPkiStatus(scope),
    staleTime: 5000,
  });
  const pairsQuery = useQuery({
    queryKey: ["admin", "pki", "pairs", scope],
    queryFn: () => listPkiPairs(scope, isSuper ? null : userTenantId),
    staleTime: 5000,
  });
  const tenantsQuery = useQuery({
    queryKey: ["admin", "tenants", scope],
    queryFn: () => listTenants(scope),
    enabled: isSuper,
    staleTime: 5000,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["admin", "pki"] });
  };

  const createMutation = useMutation({
    mutationFn: (body: CreatePkiPairBody) => createPkiPair(scope, body),
    onSuccess: invalidate,
  });
  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokePkiPair(scope, id),
    onSuccess: invalidate,
  });

  return {
    statusQuery,
    pairsQuery,
    tenantsQuery,
    createMutation,
    revokeMutation,
    invalidate,
  };
}

/** Download the one-time tar and hand it to the browser. */
export async function downloadPkiBundle(scope: ApiScope, pair: PkiPair): Promise<void> {
  const blob = await downloadPkiPair(scope, pair.id);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `hlmg-client-${pair.name}.tar`;
  anchor.click();
  URL.revokeObjectURL(url);
}
