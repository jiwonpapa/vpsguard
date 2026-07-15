import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { TrafficChart } from "../components/traffic-chart";
import { api } from "../lib/api";
import { formatBytes, formatLatency, percent } from "../lib/utils";

export function TrafficPage() {
  const [resolution, setResolution] = useState<"1s" | "10s" | "1m">("1m");
  const series = useQuery({
    queryKey: ["series", resolution],
    queryFn: () => api.series(resolution),
    refetchInterval: resolution === "1s" ? 2_000 : 10_000,
  });
  const summary = useQuery({ queryKey: ["summary"], queryFn: api.summary, refetchInterval: 5_000 });
  if (series.isPending || summary.isPending) return <LoadingState />;
  if (series.error || summary.error) return <ErrorState message="트래픽 시계열을 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading
        eyebrow="Traffic telemetry"
        title="실시간 요청 흐름"
        description="원본 query와 body를 저장하지 않는 1초 live·10초 detail·1분 장기 aggregate입니다."
        action={
          <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
            해상도
            <select
              aria-label="시계열 해상도"
              value={resolution}
              onChange={(event) => setResolution(event.target.value as "1s" | "10s" | "1m")}
              className="border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-200"
            >
              <option value="1s">1초 live</option>
              <option value="10s">10초 detail</option>
              <option value="1m">1분 aggregate</option>
            </select>
          </label>
        }
      />
      <div className="mb-8 grid grid-cols-2 border-y border-zinc-800 lg:grid-cols-5">
        <Quick label="전체 요청" value={summary.data.requests.toLocaleString()} />
        <Quick label="p95" value={formatLatency(summary.data.latency_p95_micros)} />
        <Quick label="5xx" value={summary.data.status_5xx.toLocaleString()} />
        <Quick label="전송 body" value={formatBytes(summary.data.request_body_bytes + summary.data.response_body_bytes)} />
        <Quick
          label="연결 재사용"
          value={`${percent(summary.data.upstream_connections_reused, summary.data.upstream_connections)}%`}
        />
      </div>
      <TrafficChart points={series.data} resolution={resolution} />
    </>
  );
}

function Quick({ label, value }: { label: string; value: string }) {
  return <div className="border-r border-zinc-800 px-4 py-5 last:border-r-0"><div className="text-xs text-zinc-500">{label}</div><div className="mt-2 font-mono text-xl">{value}</div></div>;
}
