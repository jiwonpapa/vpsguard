import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorState, LoadingState } from "../components/query-state";
import { DataTable } from "../components/data-table";
import { ConsoleSection, MetricGrid, MetricItem } from "../components/console-section";
import { SectionHeading } from "../components/section-heading";
import { TrafficChart } from "../components/traffic-chart";
import { Label } from "../components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
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
  const bots = useQuery({ queryKey: ["bots"], queryFn: api.bots, refetchInterval: 10_000 });
  if (series.isPending || summary.isPending || bots.isPending) return <LoadingState />;
  if (series.error || summary.error || bots.error) return <ErrorState message="트래픽 시계열을 읽지 못했습니다." />;
  return (
    <>
      <SectionHeading
        eyebrow="Traffic telemetry"
        title="실시간 요청 흐름"
        description="원본 query와 body를 저장하지 않는 1초 live·10초 detail·1분 장기 aggregate입니다."
        action={
          <div className="flex items-center gap-2">
            <Label htmlFor="traffic-resolution" className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">해상도</Label>
            <Select value={resolution} onValueChange={(value) => setResolution(value as "1s" | "10s" | "1m")}>
              <SelectTrigger id="traffic-resolution" aria-label="시계열 해상도" className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="1s">1초 live</SelectItem><SelectItem value="10s">10초 detail</SelectItem><SelectItem value="1m">1분 aggregate</SelectItem></SelectContent>
            </Select>
          </div>
        }
      />
      <div className="space-y-6">
        <ConsoleSection
          label="현재 트래픽 요약"
          title="현재 트래픽 요약"
          description="현재 control 수집 창의 핵심 요청·오류·전송 지표입니다."
          contentClassName="p-0 sm:p-0"
        >
          <MetricGrid className="xl:grid-cols-5">
            <MetricItem label="최근 10초 RPS" value={(summary.data.requests_per_second_milli / 1_000).toFixed(1)} />
            <MetricItem label="시간창 요청" value={summary.data.requests.toLocaleString()} note={`${summary.data.window_seconds}초`} />
            <MetricItem label="p95" value={formatLatency(summary.data.latency_p95_micros)} />
            <MetricItem label="Bot 요청 · 차단" value={`${summary.data.bot_requests.toLocaleString()} · ${summary.data.bot_denied.toLocaleString()}`} emphasis={summary.data.bot_denied > 0} />
            <MetricItem label="Edge 전송 손실" value={summary.data.edge_telemetry_dropped.toLocaleString()} note={`재연결 ${summary.data.edge_telemetry_reconnected}`} emphasis={summary.data.edge_telemetry_dropped > 0} />
          </MetricGrid>
          <div className="flex flex-wrap gap-x-5 gap-y-1 border-t px-5 py-4 font-mono text-[10px] text-muted-foreground sm:px-6">
            <span>처리 중 {summary.data.in_flight_requests.toLocaleString()}</span>
            <span>5xx {summary.data.status_5xx.toLocaleString()}</span>
            <span>body {formatBytes(summary.data.request_body_bytes + summary.data.response_body_bytes)}</span>
            <span>연결 재사용 {percent(summary.data.upstream_connections_reused, summary.data.upstream_connections + summary.data.upstream_connections_reused)}%</span>
            <span>edge emitted {summary.data.edge_telemetry_emitted.toLocaleString()}</span>
          </div>
        </ConsoleSection>
        <ConsoleSection
          label="요청 시계열"
          title="요청 시계열"
          description={`${resolution} 해상도의 요청량 변화입니다. 원본 query와 body는 저장하지 않습니다.`}
          contentClassName="p-0 sm:p-0"
        >
          <TrafficChart points={series.data} resolution={resolution} />
        </ConsoleSection>
        <ConsoleSection
          label="자동화 요청 분류"
          title="검색 crawler와 선언형 bot"
          description="User-Agent 원문 대신 검증 결과·provider·bounded family만 1분 aggregate로 저장합니다."
          contentClassName="p-0 sm:p-0"
        >
          <DataTable headers={["분류", "Provider", "검증", "UA family", "요청", "거부·제한", "응답 트래픽"]} empty={bots.data.length === 0}>
            {bots.data.map((bot) => (
              <tr key={`${bot.bot_class}:${bot.bot_provider}:${bot.bot_reason}:${bot.user_agent_family}`} className="transition-colors hover:bg-muted/35">
                <td className="px-4 py-3 font-medium">{bot.bot_class.replaceAll("_", " ")}</td>
                <td className="px-4 py-3 font-mono text-xs">{bot.bot_provider ?? "—"}</td>
                <td className="px-4 py-3">{bot.bot_verified ? "확인됨" : "미확인"}</td>
                <td className="px-4 py-3 font-mono text-xs">{bot.user_agent_family}</td>
                <td className="px-4 py-3 text-right tabular-nums">{bot.requests.toLocaleString()}</td>
                <td className="px-4 py-3 text-right tabular-nums">{bot.denied.toLocaleString()} · {bot.throttled.toLocaleString()}</td>
                <td className="px-4 py-3 text-right tabular-nums">{formatBytes(bot.response_body_bytes)}</td>
              </tr>
            ))}
          </DataTable>
        </ConsoleSection>
      </div>
    </>
  );
}
