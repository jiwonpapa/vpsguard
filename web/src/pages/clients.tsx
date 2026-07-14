import { useQuery } from "@tanstack/react-query";

import { DataTable } from "../components/data-table";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { api } from "../lib/api";
import { formatTime } from "../lib/utils";

export function ClientsPage() {
  const query = useQuery({ queryKey: ["clients"], queryFn: api.clients, refetchInterval: 10_000 });
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="Client aggregate를 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading eyebrow="Client aggregates" title="외부 클라이언트" description="보존기간 안에서만 원본 IP를 유지하며 요청 수 기준으로 정렬합니다." />
      <DataTable headers={["Client IP", "요청", "제한", "거부", "마지막 관측"]} empty={query.data.length === 0}>
        {query.data.map((client) => (
          <tr key={client.client_ip} className="hover:bg-zinc-900/70">
            <td className="px-3 py-3 font-mono text-zinc-200">{client.client_ip}</td>
            <td className="px-3 py-3 font-mono">{client.requests.toLocaleString()}</td>
            <td className="px-3 py-3"><Badge variant={client.throttled ? "warning" : "neutral"}>{client.throttled}</Badge></td>
            <td className="px-3 py-3"><Badge variant={client.denied ? "danger" : "neutral"}>{client.denied}</Badge></td>
            <td className="px-3 py-3 text-zinc-500">{formatTime(client.last_seen_unix_ms)}</td>
          </tr>
        ))}
      </DataTable>
    </>
  );
}
