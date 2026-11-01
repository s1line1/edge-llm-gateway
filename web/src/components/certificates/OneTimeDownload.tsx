import type { PkiPair } from "../../api/types";
import { Button } from "../ui";

export function OneTimeDownload({
  pair,
  error,
  onDownload,
}: {
  pair: PkiPair;
  error: string | null;
  onDownload: () => void;
}) {
  return (
    <div className="mt-4 rounded-lg border border-signal/25 bg-signal/6 p-4">
      <div className="text-[12px] font-medium text-paper">凭证已创建</div>
      <p className="mt-1 text-[11px] leading-relaxed text-mist">
        client 私钥只下载一次；下载后服务器会删除它。请立即保存。
      </p>
      <div className="mt-3 space-y-2">
        <div>
          <div className="micro-label">Server name (SNI)</div>
          <div className="mt-1 break-all font-mono text-[11px] text-paper">{pair.server_name}</div>
        </div>
        <div className="font-mono text-[10px] text-mist-dim">serial {pair.serial}</div>
        <Button type="button" onClick={onDownload}>
          下载 client 包
        </Button>
      </div>
      {error && <p className="mt-2 text-[10px] text-coral">{error}</p>}
    </div>
  );
}
