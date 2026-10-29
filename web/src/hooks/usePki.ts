import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  createPkiPair,
  downloadPkiPair,
  fetchPkiStatus,
  listPkiPairs,
  listTenants,
  revokePkiPair,
} from "../api/client";
import type { CreatePkiPairBody, PkiPair } from "../api/types";

export function usePki(isSuper: boolean, userTenantId: string | null) {
  const queryClient = useQueryClient();
  const statusQuery = useQuery({
    queryKey: ["admin", "pki", "status"],
    queryFn: fetchPkiStatus,
    staleTime: 5000,
  });
  const pairsQuery = useQuery({
    queryKey: ["admin", "pki", "pairs"],
    queryFn: () => listPkiPairs(isSuper ? null : userTenantId),
    staleTime: 5000,
  });
  const tenantsQuery = useQuery({
    queryKey: ["admin", "tenants"],
    queryFn: listTenants,
    enabled: isSuper,
    staleTime: 5000,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["admin", "pki"] });
  };

  const createMutation = useMutation({
    mutationFn: (body: CreatePkiPairBody) => createPkiPair(body),
    onSuccess: invalidate,
  });
  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokePkiPair(id),
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
export async function downloadPkiBundle(pair: PkiPair): Promise<void> {
  const blob = await downloadPkiPair(pair.id);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `hlmg-client-${pair.name}.tar`;
  anchor.click();
  URL.revokeObjectURL(url);
}
