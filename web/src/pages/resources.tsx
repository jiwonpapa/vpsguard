import { useQuery } from "@tanstack/react-query";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { api } from "../lib/api";
import { formatBytes, formatTime } from "../lib/utils";

export function ResourcesPage() {
  const query = useQuery({ queryKey: ["resources"], queryFn: api.resources, refetchInterval: 5_000 });
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="Collector 상태를 읽지 못했습니다." />;
  const { os, services, storage } = query.data;
  return (
    <>
      <SectionHeading eyebrow="Read-only collectors" title="서버 자원과 서비스" description="모든 probe는 독립 timeout을 가지며 Edge 요청 경로와 분리됩니다." />
      <dl className="mb-10 grid grid-cols-2 border-y border-zinc-800 lg:grid-cols-4">
        <Resource label="Load 1m" value={os?.load_1m.toFixed(2) ?? "—"} />
        <Resource label="메모리 가용" value={formatBytes(os?.memory_available_bytes)} />
        <Resource label="Swap 여유" value={formatBytes(os?.swap_free_bytes)} />
        <Resource label="Uptime" value={os ? `${Math.floor(os.uptime_seconds / 3600)} h` : "—"} />
      </dl>
      <section className="mb-10" aria-label="저장 계층 상태">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">로그·분석 저장 계층</h2>
            <p className="mt-1 text-xs text-zinc-500">
              Queue 손실, SQLite·WAL 예산과 retention 실행 상태입니다.
            </p>
          </div>
          <Badge
            variant={
              storage.condition === "healthy"
                ? "live"
                : storage.condition === "critical"
                  ? "danger"
                  : "warning"
            }
          >
            {storage.condition}
          </Badge>
        </div>
        <dl className="grid grid-cols-2 border-y border-zinc-800 lg:grid-cols-4">
          <Resource
            label="저장 Queue"
            value={`${storage.queue_depth.toLocaleString()} / ${storage.queue_capacity.toLocaleString()}`}
          />
          <Resource
            label="손실 Sample"
            value={(storage.queue_dropped_samples + storage.write_dropped_samples).toLocaleString()}
          />
          <Resource
            label="DB + WAL"
            value={formatBytes(storage.database_bytes + storage.wal_bytes)}
          />
          <Resource label="Disk 여유" value={formatBytes(storage.disk_available_bytes)} />
        </dl>
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-600">
          <span>persisted {storage.persisted_samples.toLocaleString()}</span>
          <span>retention deleted {storage.retention_deleted_rows.toLocaleString()}</span>
          <span>last rollup {formatTime(storage.last_rollup_at_unix_ms ?? "")}</span>
          <span>last retention {formatTime(storage.last_retention_at_unix_ms ?? "")}</span>
        </div>
      </section>
      <div className="border-y border-zinc-800">
        {services.map((service) => (
          <div key={service.name} className="grid grid-cols-[1fr_auto] items-center border-b border-zinc-800 px-3 py-4 last:border-b-0 md:grid-cols-[180px_140px_1fr]">
            <strong className="text-sm uppercase">{service.name}</strong>
            <Badge variant={service.state === "live" ? "live" : service.state === "unavailable" ? "neutral" : "danger"}>{service.state}</Badge>
            <span className="hidden text-right font-mono text-[10px] text-zinc-600 md:block">{service.error_code ?? formatTime(service.last_success_at ?? "")}</span>
          </div>
        ))}
      </div>
    </>
  );
}

function Resource({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-r border-zinc-800 px-4 py-5 lg:border-b-0"><dt className="text-xs text-zinc-500">{label}</dt><dd className="mt-2 font-mono text-xl">{value}</dd></div>;
}
