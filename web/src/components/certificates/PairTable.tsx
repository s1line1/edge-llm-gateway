import type { PkiPair } from "../../api/types";
import { Badge, Button, EmptyState } from "../ui";
import { formatPkiTime, pkiStatusTone } from "./format";

export function PairTable({
  pairs,
  pending,
  error,
  onDownload,
  onRevoke,
  revokePending,
}: {
  pairs: PkiPair[];
  pending: boolean;
  error: Error | null;
  onDownload: (pair: PkiPair) => void;
  onRevoke: (pair: PkiPair) => void;
  revokePending: boolean;
}) {
  if (pending) return <EmptyState title="加载中…" detail="正在读取凭证状态。" />;
  if (error) return <EmptyState title="加载失败" detail={error.message} />;
  if (pairs.length === 0) {
    return (
      <EmptyState
        title="还没有凭证"
        detail="Gateway 启动时不会自动生成 CA 或证书；需要时创建第一对。"
        icon="shield"
      />
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="data-table w-full">
        <thead>
          <tr>
            <th>名称</th>
            <th>Tenant</th>
            <th>Server name</th>
            <th>状态</th>
            <th>最后连接</th>
            <th>client 到期</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {pairs.map((pair) => (
            <tr key={pair.id}>
              <td className="font-mono text-[11px] text-paper">{pair.name}</td>
              <td>
                <Badge tone="cyan">{pair.tenant_id}</Badge>
              </td>
              <td className="font-mono text-[10px] text-mist">{pair.server_name}</td>
              <td>
                <Badge tone={pkiStatusTone(pair.status)}>{pair.status}</Badge>
              </td>
              <td className="font-mono text-[10px] text-mist">
                {formatPkiTime(pair.last_connected_at)}
              </td>
              <td className="font-mono text-[10px] text-mist">
                {formatPkiTime(pair.client_not_after)}
              </td>
              <td>
                <div className="flex flex-wrap gap-2">
                  {pair.download_url && pair.status !== "revoked" && (
                    <Button type="button" variant="secondary" onClick={() => onDownload(pair)}>
                      下载
                    </Button>
                  )}
                  {pair.status !== "revoked" && (
                    <Button
                      type="button"
                      variant="ghost"
                      disabled={revokePending}
                      onClick={() => onRevoke(pair)}
                    >
                      吊销
                    </Button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
