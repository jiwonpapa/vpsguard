import { useQuery } from "@tanstack/react-query";

import { DataTable } from "../components/data-table";
import { ConsoleSection } from "../components/console-section";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { api } from "../lib/api";
import { formatBytes, formatLatency } from "../lib/utils";

export function RoutesPage() {
  const query = useQuery({ queryKey: ["routes"], queryFn: api.routes, refetchInterval: 10_000 });
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="Route aggregate를 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading eyebrow="Normalized routes" title="경로 비용과 오류" description="숫자·UUID identifier와 query를 제거한 bounded route key입니다." />
      <ConsoleSection
        label="경로 목록"
        title="경로 목록"
        description={`정규화된 경로 ${query.data.length.toLocaleString()}개 · 비용과 5xx를 함께 비교합니다.`}
        contentClassName="p-0 sm:p-0"
      >
        <DataTable headers={["정규화 경로", "Class", "비용", "요청", "5xx", "전송 body", "평균 지연"]} empty={query.data.length === 0}>
          {query.data.map((route) => (
            <tr key={`${route.route_class}:${route.normalized_route}`} className="transition-colors hover:bg-muted/35">
              <td className="max-w-md truncate px-4 py-3 font-mono text-foreground">{route.normalized_route}</td>
              <td className="px-4 py-3"><Badge variant="neutral">{route.route_class}</Badge></td>
              <td className="px-4 py-3 font-mono">{route.max_route_cost}</td>
              <td className="px-4 py-3 font-mono">{route.requests.toLocaleString()}</td>
              <td className="px-4 py-3 font-mono text-red-400">{route.errors.toLocaleString()}</td>
              <td className="px-4 py-3 font-mono text-muted-foreground">{formatBytes(route.request_body_bytes + route.response_body_bytes)}</td>
              <td className="px-4 py-3 font-mono text-muted-foreground">{formatLatency(route.latency_avg_micros)}</td>
            </tr>
          ))}
        </DataTable>
      </ConsoleSection>
    </>
  );
}
