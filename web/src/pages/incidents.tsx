import { useQuery } from "@tanstack/react-query";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { api } from "../lib/api";
import { formatTime } from "../lib/utils";

export function IncidentsPage() {
  const query = useQuery({ queryKey: ["incidents"], queryFn: api.incidents, refetchInterval: 10_000 });
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="사건 timeline을 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading eyebrow="Audit timeline" title="사건과 운영 명령" description="상태 전이 근거, 적용 결과와 복구 조건을 한 timeline에서 확인합니다." />
      <ol className="border-y border-zinc-800">
        {query.data.map((row) => (
          <li key={row.event_id} className="grid gap-3 border-b border-zinc-800 px-2 py-5 last:border-b-0 md:grid-cols-[150px_120px_1fr]">
            <time className="font-mono text-[10px] text-zinc-600">{formatTime(row.occurred_at)}</time>
            <div><Badge variant={row.severity === "critical" ? "danger" : row.severity === "warning" ? "warning" : "neutral"}>{row.kind}</Badge></div>
            <div>
              <div className="text-sm text-zinc-200">{row.payload.summary}</div>
              <div className="mt-2 font-mono text-[10px] uppercase tracking-wide text-zinc-600">{row.payload.reason_codes.join(" · ") || "operator initiated"}</div>
            </div>
          </li>
        ))}
        {query.data.length === 0 ? <li className="py-16 text-center text-xs text-zinc-600">기록된 사건이 없습니다.</li> : null}
      </ol>
    </>
  );
}
