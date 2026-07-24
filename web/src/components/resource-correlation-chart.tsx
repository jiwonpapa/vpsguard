import { useState } from "react";

import type {
  ResourceCorrelationSeries,
  RouteResourceSeries,
  ServiceResourceSeries,
} from "../lib/types";
import { formatTime } from "../lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";

interface Line {
  label: string;
  color: string;
  values: Map<number, number>;
}

export function ResourceCorrelationChart({
  series,
}: {
  series: ResourceCorrelationSeries;
}) {
  const [routeName, setRouteName] = useState(series.routes[0]?.normalized_route ?? "");
  const [serviceName, setServiceName] = useState(series.services[0]?.name ?? "");
  const route = series.routes.find((item) => item.normalized_route === routeName) ?? series.routes[0];
  const service = series.services.find((item) => item.name === serviceName) ?? series.services[0];
  const lines = chartLines(series, route, service);
  const buckets = [...new Set(lines.flatMap((line) => [...line.values.keys()]))].sort((a, b) => a - b);

  if (buckets.length === 0) {
    return <div className="grid h-64 place-items-center text-xs text-muted-foreground">1분 상관 표본 대기 중</div>;
  }

  const width = 900;
  const height = 280;
  const padding = 20;
  const first = buckets[0] ?? 0;
  const last = buckets.at(-1) ?? first;
  const span = Math.max(1, last - first);
  const x = (bucket: number) => padding + ((bucket - first) / span) * (width - padding * 2);
  const y = (value: number) => height - padding - (Math.min(100, Math.max(0, value)) / 100) * (height - padding * 2);

  return (
    <figure className="px-5 py-5 sm:px-6">
      <div className="mb-4 flex flex-wrap gap-3">
        {series.routes.length > 0 && (
          <Select value={route?.normalized_route} onValueChange={setRouteName}>
            <SelectTrigger aria-label="비교 경로" className="max-w-64"><SelectValue /></SelectTrigger>
            <SelectContent>{series.routes.map((item) => <SelectItem key={`${item.route_class}:${item.normalized_route}`} value={item.normalized_route}>{item.normalized_route}</SelectItem>)}</SelectContent>
          </Select>
        )}
        {series.services.length > 0 && (
          <Select value={service?.name} onValueChange={setServiceName}>
            <SelectTrigger aria-label="비교 서비스" className="max-w-64"><SelectValue /></SelectTrigger>
            <SelectContent>{series.services.map((item) => <SelectItem key={item.name} value={item.name}>{item.name}</SelectItem>)}</SelectContent>
          </Select>
        )}
      </div>
      <svg className="h-72 w-full" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="트래픽·서버 자원 동일 시간축">
        {[25, 50, 75].map((value) => <line key={value} x1={padding} x2={width - padding} y1={y(value)} y2={y(value)} stroke="currentColor" className="text-border" />)}
        {lines.map((line) => {
          const points = [...line.values.entries()].sort(([a], [b]) => a - b).map(([bucket, value]) => `${x(bucket)},${y(value)}`).join(" ");
          return <polyline key={line.label} points={points} fill="none" stroke={line.color} strokeWidth="2.5" vectorEffect="non-scaling-stroke" />;
        })}
      </svg>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs">
        {lines.map((line) => <span key={line.label} className="flex items-center gap-2"><i className="size-2 rounded-full" style={{ backgroundColor: line.color }} />{line.label}</span>)}
      </div>
      <figcaption className="mt-3 flex justify-between gap-3 font-mono text-[10px] text-muted-foreground">
        <span>{formatTime(first)}</span>
        <span>경로 요청은 선택 구간 최대값 대비 비율</span>
        <span>{formatTime(last)}</span>
      </figcaption>
    </figure>
  );
}

function chartLines(
  series: ResourceCorrelationSeries,
  route: RouteResourceSeries | undefined,
  service: ServiceResourceSeries | undefined,
): Line[] {
  const lines: Line[] = [
    { label: "OS CPU", color: "#f97316", values: new Map(series.os.flatMap((point) => point.cpu_usage_percent == null ? [] : [[point.bucket_unix_ms, point.cpu_usage_percent]])) },
    { label: "OS memory", color: "#0ea5e9", values: new Map(series.os.map((point) => [point.bucket_unix_ms, point.memory_used_percent])) },
  ];
  if (route) {
    const max = Math.max(1, ...route.points.map((point) => point.requests));
    lines.push({ label: `${route.normalized_route} requests`, color: "#a855f7", values: new Map(route.points.map((point) => [point.bucket_unix_ms, (point.requests / max) * 100])) });
  }
  if (service) {
    lines.push({
      label: `${service.name} pressure`,
      color: "#22c55e",
      values: new Map(service.points.map((point) => [
        point.bucket_unix_ms,
        Math.max((point.cpu_usage_milli_percent ?? 0) / 1_000, point.semantic_pressure_percent ?? 0),
      ])),
    });
  }
  return lines.filter((line) => line.values.size > 0);
}
