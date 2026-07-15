import { useQuery } from "@tanstack/react-query";
import { CloudCog, Pause, Play, RotateCcw, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { useAuth } from "../auth";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { api } from "../lib/api";
import type { CertbotAssistedPlan } from "../lib/types";
import { formatBytes, formatLatency, formatTime, MODE_LABELS, percent } from "../lib/utils";

export function OverviewPage() {
  const { runAction } = useAuth();
  const [tlsEmail, setTlsEmail] = useState("");
  const [tlsPlan, setTlsPlan] = useState<CertbotAssistedPlan | null>(null);
  const [tlsPlanError, setTlsPlanError] = useState("");
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 5_000 });
  const summary = useQuery({ queryKey: ["summary"], queryFn: api.summary, refetchInterval: 5_000 });
  const resources = useQuery({ queryKey: ["resources"], queryFn: api.resources, refetchInterval: 5_000 });

  if (status.isPending || summary.isPending || resources.isPending) return <LoadingState />;
  if (status.error || summary.error || resources.error) {
    return <ErrorState message="Control API 응답을 읽지 못했습니다. SSH tunnel과 control 상태를 확인하십시오." />;
  }

  const state = status.data;
  const traffic = summary.data;
  const resource = resources.data;
  const blocked = traffic.throttled + traffic.denied + traffic.challenged;
  const memoryUsed = resource.os
    ? resource.os.memory_total_bytes - resource.os.memory_available_bytes
    : null;

  return (
    <>
      <SectionHeading
        eyebrow="Protection posture"
        title="현재 방어 상태"
        description={state.reasons[0] ?? "상태 전이 근거를 기다리고 있습니다."}
        action={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => void runAction("/api/v1/actions/manual-hold")}>
              <Pause className="size-3.5" /> 자동 대응 중지
            </Button>
            <Button onClick={() => void runAction("/api/v1/actions/resume-auto")}>
              <Play className="size-3.5" /> 자동 대응 재개
            </Button>
          </div>
        }
      />

      <section className="mb-10 border-y border-zinc-800 py-7">
        <div className="flex flex-wrap items-end justify-between gap-5">
          <div className="flex items-center gap-5">
            <ShieldAlert className="size-9 text-orange-400" aria-hidden="true" />
            <div>
              <div className="text-4xl font-semibold tracking-[-0.04em] md:text-6xl">
                {MODE_LABELS[state.mode] ?? state.mode}
              </div>
              <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-zinc-500">
                마지막 전이 {formatTime(state.last_transition_at)} · 정책 v{state.policy_version}
              </div>
            </div>
          </div>
          <Badge variant={state.mode === "NORMAL" ? "live" : state.mode === "EMERGENCY_PROXY" ? "danger" : "warning"}>
            {state.manual_hold ? "manual" : "automatic"}
          </Badge>
        </div>
      </section>

      <section aria-label="서비스 상태" className="mb-10 grid grid-cols-2 border-y border-zinc-800 md:grid-cols-5">
        {(["edge", "origin", "agent", "provider", "tls"] as const).map((key) => (
          <div key={key} className="border-b border-r border-zinc-800 px-3 py-4 last:border-r-0 md:border-b-0">
            <div className="font-mono text-[9px] font-bold uppercase tracking-widest text-zinc-600">{key}</div>
            <div className="mt-1 text-xs font-semibold uppercase text-zinc-300">{state[key]}</div>
          </div>
        ))}
      </section>

      {state.tls_management.health !== "disabled" ? (
        <section className="mb-10 border-b border-zinc-800 pb-5" aria-label="TLS 관리 상태">
          <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
            <div>
              <div className="text-sm font-semibold">TLS certificate lifecycle</div>
              <div className="mt-1 font-mono text-[10px] uppercase tracking-wider text-zinc-600">
                owner {state.tls_management.ownership} · renewal {state.tls_management.renewal}
                {state.tls_management.manager ? ` · ${state.tls_management.manager}` : ""}
              </div>
              <p className="mt-3 max-w-3xl text-xs leading-5 text-zinc-400">{state.tls_management.next_action}</p>
              {state.tls_management.ownership === "vpsguard_assisted" &&
              state.tls_management.renewal !== "healthy" ? (
                <div className="mt-4 max-w-xl">
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <input
                      type="email"
                      autoComplete="email"
                      value={tlsEmail}
                      onChange={(event) => setTlsEmail(event.target.value)}
                      placeholder="ACME 연락처 email"
                      className="min-w-0 flex-1 border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 outline-none focus:border-orange-500"
                    />
                    <Button
                      variant="outline"
                      onClick={() => {
                        setTlsPlanError("");
                        void api
                          .tlsAssistedPlan(tlsEmail)
                          .then(setTlsPlan)
                          .catch((error: Error) => setTlsPlanError(error.message));
                      }}
                    >
                      Certbot 계획 보기
                    </Button>
                  </div>
                  {tlsPlanError ? <p className="mt-2 text-xs text-red-400">{tlsPlanError}</p> : null}
                  {tlsPlan ? (
                    <ol className="mt-3 list-decimal space-y-1 pl-5 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                      {tlsPlan.steps.map((step) => (
                        <li key={step}>{step.replaceAll("_", " ")}</li>
                      ))}
                    </ol>
                  ) : null}
                </div>
              ) : null}
            </div>
            <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
              {state.tls_management.earliest_expiry
                ? `expires ${formatTime(state.tls_management.earliest_expiry)}`
                : "expiry unavailable"}
            </div>
          </div>
        </section>
      ) : null}

      {state.provider !== "unavailable" ? (
        <section className="mb-10 flex flex-wrap items-center justify-between gap-4 border-b border-zinc-800 pb-5">
          <div className="min-w-64 flex-1">
            <div className="text-sm font-semibold">Cloudflare transaction</div>
            <div className="mt-1 font-mono text-[10px] uppercase tracking-wider text-zinc-600">read-back stage: {state.provider}</div>
            <div className="mt-3 h-1.5 max-w-lg overflow-hidden bg-zinc-900" aria-label={`Provider 진행률 ${providerProgress(state.provider)}%`}>
              <div className="h-full bg-orange-500 transition-[width]" style={{ width: `${providerProgress(state.provider)}%` }} />
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="danger" onClick={() => void runAction("/api/v1/actions/emergency-proxy")}>
              <CloudCog className="size-3.5" /> 비상 보호
            </Button>
            <Button variant="outline" onClick={() => void runAction("/api/v1/actions/provider-restore")}>
              <RotateCcw className="size-3.5" /> Snapshot 복구
            </Button>
          </div>
        </section>
      ) : null}

      <section>
        <div className="mb-4 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-orange-400">Live window</div>
        <div className="grid grid-cols-2 border-t border-zinc-800 lg:grid-cols-4">
          <Metric label="수집 요청" value={traffic.requests.toLocaleString()} note="control lifetime" />
          <Metric label="p95 지연" value={formatLatency(traffic.latency_p95_micros)} note="최근 2,048 요청" />
          <Metric label="고유 client" value={traffic.unique_clients.toLocaleString()} note={`overflow ${traffic.dropped_clients}`} />
          <Metric label="방어 판정" value={blocked.toLocaleString()} note={`${percent(blocked, traffic.requests)}% of traffic`} alert />
        </div>
        <dl className="mt-5 grid grid-cols-2 border-y border-zinc-800 lg:grid-cols-4">
          <Resource label="요청 body" value={formatBytes(traffic.request_body_bytes)} />
          <Resource label="응답 body" value={formatBytes(traffic.response_body_bytes)} />
          <Resource label="Upstream 연결" value={traffic.upstream_connections.toLocaleString()} />
          <Resource
            label="연결 재사용"
            value={`${traffic.upstream_connections_reused.toLocaleString()} (${percent(traffic.upstream_connections_reused, traffic.upstream_connections)}%)`}
          />
        </dl>
        <div className="mt-5 flex h-9 overflow-hidden bg-zinc-900 text-[10px] font-bold">
          <StatusSegment label="2xx" value={traffic.status_2xx} total={traffic.requests} className="bg-emerald-800" />
          <StatusSegment label="3xx" value={traffic.status_3xx} total={traffic.requests} className="bg-sky-900" />
          <StatusSegment label="4xx" value={traffic.status_4xx} total={traffic.requests} className="bg-amber-800" />
          <StatusSegment label="5xx" value={traffic.status_5xx} total={traffic.requests} className="bg-red-900" />
        </div>
      </section>

      <section className="mt-12">
        <div className="mb-4 font-mono text-[10px] font-bold uppercase tracking-[0.18em] text-orange-400">Server pressure</div>
        <dl className="grid grid-cols-2 border-y border-zinc-800 lg:grid-cols-4">
          <Resource label="Load 1m" value={resource.os?.load_1m.toFixed(2) ?? "—"} />
          <Resource label="메모리 사용" value={memoryUsed == null ? "—" : formatBytes(memoryUsed)} />
          <Resource label="Swap 사용" value={resource.os ? formatBytes(resource.os.swap_total_bytes - resource.os.swap_free_bytes) : "—"} />
          <Resource label="Uptime" value={resource.os ? `${Math.floor(resource.os.uptime_seconds / 3600)} h` : "—"} />
        </dl>
      </section>
    </>
  );
}

function providerProgress(stage: string): number {
  return {
    ready: 0,
    pending: 5,
    snapshotted: 20,
    proxy_requested: 40,
    proxy_verified: 60,
    origin_lock_requested: 80,
    running: 90,
    complete: 100,
    restored: 100,
  }[stage] ?? 0;
}

function Metric({ label, value, note, alert = false }: { label: string; value: string; note: string; alert?: boolean }) {
  return (
    <div className="border-b border-r border-zinc-800 py-5 pr-4 lg:border-b-0">
      <div className="text-xs text-zinc-500">{label}</div>
      <strong className={`mt-3 block font-mono text-2xl font-medium ${alert ? "text-orange-400" : "text-zinc-100"}`}>{value}</strong>
      <small className="mt-1 block font-mono text-[10px] text-zinc-600">{note}</small>
    </div>
  );
}

function StatusSegment({ label, value, total, className }: { label: string; value: number; total: number; className: string }) {
  const weight = Math.max(1, percent(value, total));
  return (
    <span className={`grid min-w-[72px] place-items-center text-white transition-[flex-grow] ${className}`} style={{ flexGrow: weight }}>
      {label} {value}
    </span>
  );
}

function Resource({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-r border-zinc-800 px-3 py-4 lg:border-b-0">
      <dt className="text-xs text-zinc-500">{label}</dt>
      <dd className="mt-2 font-mono text-lg text-zinc-200">{value}</dd>
    </div>
  );
}
