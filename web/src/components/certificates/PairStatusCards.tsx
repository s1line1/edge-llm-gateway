import type { PkiStatus } from "../../api/types";

export function PairStatusCards({
  status,
  pairCount,
}: {
  status: PkiStatus | undefined;
  pairCount: number;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <div className="panel p-4">
        <div className="micro-label">CREDENTIALS</div>
        <div className="mt-2 font-mono text-2xl text-paper">{status?.credentials ?? 0}</div>
      </div>
      <div className="panel p-4">
        <div className="micro-label">QUIC TLS</div>
        <div className="mt-2 font-mono text-2xl text-paper">
          {status?.tunnel_ready ? "READY" : "WAITING"}
        </div>
      </div>
      <div className="panel p-4">
        <div className="micro-label">NEXT STEP</div>
        <div className="mt-2 text-[11px] text-mist">
          {pairCount === 0 ? "创建第一对凭证" : "下载 client 证书并连接"}
        </div>
      </div>
    </div>
  );
}
