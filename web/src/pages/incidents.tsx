import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { ConsoleSection } from "../components/console-section";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { api, apiErrorMessage } from "../lib/api";
import { formatLatency, formatTime } from "../lib/utils";

export function IncidentsPage() {
  const [correlationInput, setCorrelationInput] = useState("");
  const [correlationId, setCorrelationId] = useState("");
  const query = useQuery({ queryKey: ["incidents"], queryFn: api.incidents, refetchInterval: 10_000 });
  const correlation = useQuery({
    queryKey: ["correlation", correlationId],
    queryFn: () => api.correlation(correlationId),
    enabled: correlationId.length > 0,
    retry: false,
  });
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="사건 timeline을 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading eyebrow="Audit timeline" title="사건과 운영 명령" description="상태 전이 근거, 적용 결과와 복구 조건을 한 timeline에서 확인합니다." />
      <div className="space-y-6">
        <ConsoleSection
          label="상관관계 검색"
          title="요청 상관관계 추적"
          description="Request ID, operation ID 또는 event ID로 동일 사건의 요청·정책·운영 기록을 연결합니다."
        >
          <form className="flex flex-col gap-3 sm:flex-row" onSubmit={(event) => { event.preventDefault(); setCorrelationId(correlationInput.trim()); }}>
            <div className="grid min-w-0 flex-1 gap-2">
              <Label htmlFor="correlation-id" className="text-xs text-muted-foreground">상관관계 ID</Label>
              <Input id="correlation-id" value={correlationInput} onChange={(event) => setCorrelationInput(event.target.value)} placeholder="X-Request-ID, operation ID 또는 event ID" className="h-10 font-mono text-xs" />
            </div>
            <Button type="submit" className="self-end" disabled={!correlationInput.trim()}>추적</Button>
          </form>
          {correlation.isFetching ? <p className="mt-4 text-xs text-muted-foreground">상관관계를 조회하고 있습니다.</p> : null}
          {correlation.error ? <p className="mt-4 whitespace-pre-line text-xs text-red-400">{apiErrorMessage(correlation.error, "상관관계를 조회하지 못했습니다.")}</p> : null}
          {correlation.data ? <CorrelationResult value={correlation.data} /> : null}
        </ConsoleSection>

        <ConsoleSection label="사건 타임라인" title="사건 타임라인" description={`최근 사건과 운영 명령 ${query.data.length.toLocaleString()}건`} contentClassName="p-0 sm:p-0">
          <ol>
            {query.data.map((row) => (
              <li key={row.event_id} className="grid gap-3 border-b px-5 py-5 last:border-b-0 md:grid-cols-[150px_140px_1fr] sm:px-6">
                <time className="font-mono text-[10px] text-muted-foreground">{formatTime(row.occurred_at)}</time>
                <div><Badge variant={row.severity === "critical" ? "danger" : row.severity === "warning" ? "warning" : "neutral"}>{row.kind}</Badge></div>
                <div>
                  <div className="text-sm text-foreground">{row.payload.summary}</div>
                  <div className="mt-2 font-mono text-[10px] tracking-wide text-muted-foreground">{row.payload.reason_codes.join(" · ") || "operator initiated"}</div>
                </div>
              </li>
            ))}
            {query.data.length === 0 ? <li className="py-16 text-center text-xs text-muted-foreground">기록된 사건이 없습니다.</li> : null}
          </ol>
        </ConsoleSection>
      </div>
    </>
  );
}

function CorrelationResult({ value }: { value: Awaited<ReturnType<typeof api.correlation>> }) {
  return (
    <div className="mt-5 border-t pt-5" role="region" aria-label="상관관계 조회 결과">
      <div className="font-mono text-[10px] text-muted-foreground">{value.correlation_id}</div>
      {value.request ? (
        <div className="mt-3 grid gap-2 text-xs text-foreground sm:grid-cols-2 lg:grid-cols-4">
          <strong>{value.request.method} {value.request.normalized_route}</strong>
          <span>HTTP {value.request.status} · {value.request.decision}</span>
          <span>{formatLatency(value.request.latency_micros)}</span>
          <span>policy v{value.request.policy_version}</span>
        </div>
      ) : null}
      {value.audit_action ? (
        <p className="mt-3 text-xs text-muted-foreground">
          운영 명령 {value.audit_action.action} · {value.audit_action.mode} · {value.audit_action.result}
        </p>
      ) : null}
      {value.events.length > 0 ? (
        <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
          {value.events.map((event) => <li key={event.event_id}>{event.kind} · {event.payload.summary}</li>)}
        </ul>
      ) : null}
    </div>
  );
}
