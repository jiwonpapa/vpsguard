import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
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
      <section className="mb-10 border-y border-zinc-800 py-5" aria-label="상관관계 검색">
        <form
          className="flex flex-col gap-3 sm:flex-row"
          onSubmit={(event) => {
            event.preventDefault();
            setCorrelationId(correlationInput.trim());
          }}
        >
          <label className="min-w-0 flex-1">
            <span className="mb-2 block font-mono text-[10px] font-bold uppercase tracking-widest text-zinc-500">
              상관관계 ID
            </span>
            <input
              value={correlationInput}
              onChange={(event) => setCorrelationInput(event.target.value)}
              placeholder="X-Request-ID, operation ID 또는 event ID"
              className="w-full border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200 outline-none focus:border-orange-500"
            />
          </label>
          <Button type="submit" className="self-end" disabled={!correlationInput.trim()}>
            추적
          </Button>
        </form>
        {correlation.isFetching ? <p className="mt-4 text-xs text-zinc-500">상관관계를 조회하고 있습니다.</p> : null}
        {correlation.error ? <p className="mt-4 whitespace-pre-line text-xs text-red-400">{apiErrorMessage(correlation.error, "상관관계를 조회하지 못했습니다.")}</p> : null}
        {correlation.data ? <CorrelationResult value={correlation.data} /> : null}
      </section>
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

function CorrelationResult({ value }: { value: Awaited<ReturnType<typeof api.correlation>> }) {
  return (
    <div className="mt-5 border-t border-zinc-800 pt-5" role="region" aria-label="상관관계 조회 결과">
      <div className="font-mono text-[10px] text-zinc-600">{value.correlation_id}</div>
      {value.request ? (
        <div className="mt-3 grid gap-2 text-xs text-zinc-300 sm:grid-cols-2 lg:grid-cols-4">
          <strong>{value.request.method} {value.request.normalized_route}</strong>
          <span>HTTP {value.request.status} · {value.request.decision}</span>
          <span>{formatLatency(value.request.latency_micros)}</span>
          <span>policy v{value.request.policy_version}</span>
        </div>
      ) : null}
      {value.audit_action ? (
        <p className="mt-3 text-xs text-zinc-400">
          운영 명령 {value.audit_action.action} · {value.audit_action.mode} · {value.audit_action.result}
        </p>
      ) : null}
      {value.events.length > 0 ? (
        <ul className="mt-3 space-y-1 text-xs text-zinc-400">
          {value.events.map((event) => <li key={event.event_id}>{event.kind} · {event.payload.summary}</li>)}
        </ul>
      ) : null}
    </div>
  );
}
