import { useQuery } from "@tanstack/react-query";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { api } from "../lib/api";
import type { CollectorHealth, ServiceSemanticSnapshot } from "../lib/types";
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
      <section aria-label="핵심 서비스 상태">
        <div className="mb-4">
          <h2 className="text-sm font-semibold">Allowlist 핵심 서비스</h2>
          <p className="mt-1 text-xs text-zinc-500">등록된 systemd unit의 cgroup 값과 서비스 병목 지표만 읽습니다.</p>
        </div>
        {services.length === 0 && <p className="border-y border-zinc-800 py-5 text-sm text-zinc-500">등록된 핵심 서비스가 없습니다.</p>}
        {services.map((service) => (
          <ServiceStatus key={service.name} service={service} />
        ))}
      </section>
    </>
  );
}

function ServiceStatus({ service }: { service: CollectorHealth }) {
  const resource = service.resources;
  return (
    <article className="mb-5 border-y border-zinc-800 px-3 py-4" aria-label={`${service.name} 상태`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <strong className="text-sm uppercase">{service.name}</strong>
          <p className="mt-1 font-mono text-[10px] text-zinc-600">{service.unit ?? "legacy probe"}</p>
        </div>
        <div className="flex items-center gap-2">
          <StateBadge state={service.resource_state} label="resource" />
          <StateBadge state={service.semantic_state} label="semantic" />
          <StateBadge state={service.state} />
        </div>
      </div>
      <dl className="mt-4 grid grid-cols-2 border-t border-zinc-800 lg:grid-cols-5">
        <Resource label="CPU" value={resource?.cpu_usage_milli_percent == null ? "—" : `${(resource.cpu_usage_milli_percent / 1_000).toFixed(1)}%`} />
        <Resource label="Memory" value={formatBytes(resource?.memory_current_bytes)} />
        <Resource label="I/O read · write" value={resource ? `${formatBytes(resource.io_read_bytes)} · ${formatBytes(resource.io_write_bytes)}` : "—"} />
        <Resource label="Process · task" value={resource ? `${resource.process_count} · ${resource.task_count}` : "—"} />
        <Resource label="OOM kill" value={resource?.oom_kill_events.toLocaleString() ?? "—"} />
      </dl>
      {service.semantic && <SemanticMetrics semantic={service.semantic} />}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-zinc-600">
        <span>sample {formatTime(service.collected_at_unix_ms ?? "")}</span>
        {service.resource_error_code && <span>resource {service.resource_error_code}</span>}
        {service.semantic_error_code && <span>semantic {service.semantic_error_code}</span>}
      </div>
    </article>
  );
}

function StateBadge({ state, label }: { state: string | null; label?: string }) {
  if (!state) return null;
  const variant = state === "live" ? "live" : state === "unavailable" ? "neutral" : state === "delayed" ? "warning" : "danger";
  return <Badge variant={variant}>{label ? `${label} ${state}` : state}</Badge>;
}

function SemanticMetrics({ semantic }: { semantic: ServiceSemanticSnapshot }) {
  const metrics = semanticMetrics(semantic);
  return (
    <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs">
      {metrics.map(([label, value]) => <div key={label}><dt className="text-zinc-600">{label}</dt><dd className="mt-1 font-mono">{value}</dd></div>)}
    </dl>
  );
}

function semanticMetrics(semantic: ServiceSemanticSnapshot): Array<[string, string]> {
  switch (semantic.kind) {
    case "tcp_health": return [["TCP", "connected"]];
    case "nginx": return [["Active", `${semantic.active_connections}`], ["Read · write · wait", `${semantic.reading} · ${semantic.writing} · ${semantic.waiting}`], ["Requests", semantic.requests.toLocaleString()]];
    case "apache": return [["Busy · idle", `${semantic.busy_workers} · ${semantic.idle_workers}`], ["Accesses", semantic.total_accesses.toLocaleString()]];
    case "php_fpm": return [["Queue", `${semantic.listen_queue} / ${semantic.listen_queue_length}`], ["Active · idle", `${semantic.active_processes} · ${semantic.idle_processes}`], ["Max children", semantic.max_children_reached.toLocaleString()], ["Slow", semantic.slow_requests.toLocaleString()]];
    case "mysql": return [["Connected · max", `${semantic.threads_connected} · ${semantic.max_connections}`], ["Running", semantic.threads_running.toLocaleString()], ["Lock waits", semantic.innodb_row_lock_current_waits.toLocaleString()], ["Slow", semantic.slow_queries.toLocaleString()]];
    case "redis": return [["Redis memory", formatBytes(semantic.used_memory_bytes)], ["Clients · blocked", `${semantic.connected_clients} · ${semantic.blocked_clients}`], ["Hit · miss", `${semantic.keyspace_hits} · ${semantic.keyspace_misses}`], ["Evicted", semantic.evicted_keys.toLocaleString()]];
  }
}

function Resource({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-r border-zinc-800 px-4 py-5 lg:border-b-0"><dt className="text-xs text-zinc-500">{label}</dt><dd className="mt-2 font-mono text-xl">{value}</dd></div>;
}
