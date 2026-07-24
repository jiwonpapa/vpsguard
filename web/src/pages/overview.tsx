import { useQuery } from "@tanstack/react-query";
import { BellRing, CloudCog, Pause, Play, RotateCcw, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { useAuth } from "../auth";
import { ConsoleSection, MetricGrid, MetricItem } from "../components/console-section";
import { InfrastructureReadback } from "../components/infrastructure-readback";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
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
  const firewall = useQuery({ queryKey: ["firewall"], queryFn: api.firewall, refetchInterval: 10_000 });

  if (status.isPending || summary.isPending || resources.isPending) return <LoadingState />;
  if (status.error || summary.error || resources.error) {
    return <ErrorState message="Control API 응답을 읽지 못했습니다. 관리 HTTPS 경로와 control 상태를 확인하십시오." />;
  }

  const state = status.data;
  const traffic = summary.data;
  const resource = resources.data;
  const blocked = traffic.throttled + traffic.denied + traffic.challenged;
  const memoryUsed = resource.os ? resource.os.memory_total_bytes - resource.os.memory_available_bytes : null;
  const modeVariant = state.mode === "NORMAL" ? "live" : state.mode === "EMERGENCY_PROXY" ? "danger" : "warning";

  return (
    <>
      <SectionHeading
        eyebrow="Operations overview"
        title="현재 방어 상태"
        description="사이트 상태, 방어 판정, 서버 압력과 복구 경로를 한 화면에서 확인합니다."
        action={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => void runAction("/api/v1/actions/manual-hold")}>
              <Pause className="size-3.5" /> 자동 대응 중지
            </Button>
            <Button size="sm" onClick={() => void runAction("/api/v1/actions/resume-auto")}>
              <Play className="size-3.5" /> 자동 대응 재개
            </Button>
          </div>
        }
      />

      <div className="space-y-6">
        <InfrastructureReadback
          status={state}
          firewall={firewall.data}
          firewallPending={firewall.isPending}
          firewallFailed={firewall.isError}
        />

        <ConsoleSection label="현재 보호 상태" contentClassName="p-0 sm:p-0">
          <div className="grid lg:grid-cols-[1.35fr_0.65fr]">
            <div className="p-5 sm:p-7">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex min-w-0 items-start gap-4">
                  <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
                    <ShieldAlert className="size-5" aria-hidden="true" />
                  </span>
                  <div className="min-w-0">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">현재 보호 모드</p>
                    <div className="mt-1 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">
                      {MODE_LABELS[state.mode] ?? state.mode}
                    </div>
                  </div>
                </div>
                <Badge variant={modeVariant}>{state.manual_hold ? "수동 유지" : "자동 대응"}</Badge>
              </div>

              <div className="mt-7 rounded-lg bg-muted/60 px-4 py-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-muted-foreground">판정 근거</p>
                <ul className="mt-2 space-y-1.5 text-sm leading-6">
                  {(state.reasons.length ? state.reasons : ["상태 전이 근거를 기다리고 있습니다."]).slice(0, 3).map((reason) => (
                    <li key={reason} className="flex gap-2"><span className="mt-2.5 size-1 shrink-0 rounded-full bg-primary" />{reason}</li>
                  ))}
                </ul>
              </div>

              <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 font-mono text-[10px] text-muted-foreground">
                <span>마지막 전이 {formatTime(state.last_transition_at)}</span>
                <span>정책 v{state.policy_version}</span>
                <span>inspection {state.inspection}</span>
              </div>
            </div>

            <div className="border-t bg-muted/25 p-5 lg:border-t-0 lg:border-l sm:p-7">
              <h2 className="text-sm font-semibold">보안 계층</h2>
              <dl className="mt-4 space-y-4 text-xs">
                <SecurityRow label="앱 보안" value={state.security.app_layer_active ? "활성" : "비활성"} healthy={state.security.app_layer_active} />
                <SecurityRow label="CSP" value={state.security.csp_mode} healthy={state.security.csp_mode !== "off"} />
                <SecurityRow label="외부 WAF" value={state.security.waf_mode} healthy={state.security.waf_mode !== "off"} />
                <SecurityRow
                  label="인증 한도"
                  value={state.security.auth_rate_limit_rpm === null ? "미적용" : `${state.security.auth_rate_limit_rpm}회/분`}
                  healthy={state.security.auth_rate_limit_rpm !== null}
                />
              </dl>
              <p className="mt-5 border-t pt-4 font-mono text-[10px] leading-5 text-muted-foreground">
                앱 보안 {state.security.app_layer_active ? "활성" : "비활성"} · CSP {state.security.csp_mode} · {state.security.waf_adapter.replaceAll("_", " ")}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 border-t sm:grid-cols-3 lg:grid-cols-5" aria-label="서비스 상태">
            {(["edge", "origin", "agent", "provider", "tls"] as const).map((key) => (
              <div key={key} className="border-r border-b px-5 py-4 last:border-r-0 lg:border-b-0">
                <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{key}</div>
                <div className="mt-2 flex items-center gap-2 text-xs font-semibold uppercase">
                  <span className={serviceDot(state[key])} aria-hidden="true" />{state[key]}
                </div>
              </div>
            ))}
          </div>
        </ConsoleSection>

        <ConsoleSection
          label="실시간 트래픽"
          title="실시간 트래픽"
          description="최근 수집 창의 요청량, 응답 지연과 방어 판정을 요약합니다."
          contentClassName="p-0 sm:p-0"
        >
          <MetricGrid>
            <MetricItem label="최근 10초 RPS" value={(traffic.requests_per_second_milli / 1_000).toFixed(1)} note={`${traffic.window_seconds}초 시간창`} help="관측 시간창의 요청 수를 초 단위 평균으로 환산한 값입니다." />
            <MetricItem label="p95 지연" value={formatLatency(traffic.latency_p95_micros)} note="현재 시간창 최대 2,048 요청" help="현재 시간창에서 요청 약 95%가 이 시간 안에 완료됐습니다." />
            <MetricItem label="고유 클라이언트" value={traffic.unique_clients.toLocaleString()} note={`overflow ${traffic.dropped_clients}`} />
            <MetricItem label="방어 판정" value={blocked.toLocaleString()} note={`${percent(blocked, traffic.requests)}% of traffic`} emphasis />
          </MetricGrid>
          <div className="grid border-t sm:grid-cols-2 xl:grid-cols-5">
            <CompactMetric label="처리 중 요청" value={traffic.in_flight_requests.toLocaleString()} />
            <CompactMetric label="요청 body" value={formatBytes(traffic.request_body_bytes)} />
            <CompactMetric label="응답 body" value={formatBytes(traffic.response_body_bytes)} />
            <CompactMetric label="Upstream 연결" value={traffic.upstream_connections.toLocaleString()} />
            <CompactMetric label="연결 재사용" value={`${traffic.upstream_connections_reused.toLocaleString()} (${percent(traffic.upstream_connections_reused, traffic.upstream_connections + traffic.upstream_connections_reused)}%)`} />
          </div>
          <div className="border-t px-5 py-5 sm:px-6">
            <div className="mb-3 flex items-center justify-between text-[10px] font-medium text-muted-foreground">
              <span>응답 상태 분포</span><span>총 {traffic.requests.toLocaleString()}건</span>
            </div>
            <div className="flex h-8 overflow-hidden rounded-md bg-muted text-[10px] font-semibold">
              <StatusSegment label="2xx" value={traffic.status_2xx} total={traffic.requests} className="bg-emerald-700" />
              <StatusSegment label="3xx" value={traffic.status_3xx} total={traffic.requests} className="bg-sky-700" />
              <StatusSegment label="4xx" value={traffic.status_4xx} total={traffic.requests} className="bg-amber-700" />
              <StatusSegment label="5xx" value={traffic.status_5xx} total={traffic.requests} className="bg-red-800" />
            </div>
          </div>
        </ConsoleSection>

        <ConsoleSection
          label="서버 압력"
          title="서버 압력"
          description="오리진 자원 고갈이 방어 전이의 원인인지 빠르게 확인합니다."
          contentClassName="p-0 sm:p-0"
        >
          <MetricGrid>
            <MetricItem label="CPU 사용" value={resource.os?.cpu_usage_percent == null ? "—" : `${resource.os.cpu_usage_percent}%`} />
            <MetricItem label="Load 1m" value={resource.os ? `${resource.os.load_1m.toFixed(2)} / ${resource.os.logical_cpu_count} core` : "—"} />
            <MetricItem label="메모리 사용" value={memoryUsed == null ? "—" : formatBytes(memoryUsed)} />
            <MetricItem label="Swap 사용" value={resource.os ? formatBytes(resource.os.swap_total_bytes - resource.os.swap_free_bytes) : "—"} />
            <MetricItem label="Uptime" value={resource.os ? `${Math.floor(resource.os.uptime_seconds / 3600)} h` : "—"} />
          </MetricGrid>
        </ConsoleSection>

        {state.tls_management.health !== "disabled" ? (
          <ConsoleSection
            label="TLS 관리 상태"
            title="TLS 인증서 수명주기"
            description={state.tls_management.next_action}
            action={<Badge variant={state.tls_management.renewal === "healthy" ? "live" : "warning"}>{state.tls_management.renewal}</Badge>}
          >
            <div className="grid gap-5 lg:grid-cols-[1fr_auto] lg:items-end">
              <div>
                <div className="flex flex-wrap gap-x-5 gap-y-2 font-mono text-[10px] text-muted-foreground">
                  <span>owner {state.tls_management.ownership}</span>
                  <span>manager {state.tls_management.manager ?? "unavailable"}</span>
                  <span>certificates {state.tls_management.certificate_count}</span>
                </div>
                {state.tls_management.ownership === "vpsguard_assisted" && state.tls_management.renewal !== "healthy" ? (
                  <div className="mt-5 max-w-xl">
                    <div className="flex flex-col gap-2 sm:flex-row">
                      <Input type="email" autoComplete="email" value={tlsEmail} onChange={(event) => setTlsEmail(event.target.value)} placeholder="ACME 연락처 email" className="h-9 min-w-0 flex-1 text-xs" />
                      <Button variant="outline" onClick={() => {
                        setTlsPlanError("");
                        void api.tlsAssistedPlan(tlsEmail).then(setTlsPlan).catch((error: Error) => setTlsPlanError(error.message));
                      }}>Certbot 계획 보기</Button>
                    </div>
                    {tlsPlanError ? <p className="mt-2 text-xs text-red-400">{tlsPlanError}</p> : null}
                    {tlsPlan ? <ol className="mt-3 list-decimal space-y-1 pl-5 font-mono text-[10px] text-muted-foreground">{tlsPlan.steps.map((step) => <li key={step}>{step.replaceAll("_", " ")}</li>)}</ol> : null}
                  </div>
                ) : null}
              </div>
              <div className="font-mono text-[10px] text-muted-foreground">
                {state.tls_management.earliest_expiry ? `expires ${formatTime(state.tls_management.earliest_expiry)}` : "expiry unavailable"}
              </div>
            </div>
          </ConsoleSection>
        ) : null}

        <ConsoleSection
          label="외부 알림"
          title="관리자 webhook"
          description={
            state.notification.enabled
              ? "주요 방어 전이와 provider 조치 결과를 서버 밖의 관리자에게 전달합니다."
              : "HTTPS webhook이 비활성 상태입니다. 방어는 계속되지만 서버 밖 장애 통보는 없습니다."
          }
          action={
            <Badge variant={!state.notification.enabled ? "warning" : state.notification.failed > 0 || !state.notification.storage_available ? "danger" : "live"}>
              {!state.notification.enabled ? "비활성" : state.notification.failed > 0 ? "전송 실패" : "정상"}
            </Badge>
          }
        >
          <div className="grid gap-5 lg:grid-cols-[auto_1fr] lg:items-center">
            <span className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary">
              <BellRing className="size-4" aria-hidden="true" />
            </span>
            <div>
              <div className="flex flex-wrap gap-x-5 gap-y-2 font-mono text-[10px] text-muted-foreground">
                <span>queue {state.notification.queue_depth}/{state.notification.queue_capacity}</span>
                <span>delivered {state.notification.delivered}</span>
                <span>pending {state.notification.pending}</span>
                <span>failed {state.notification.failed}</span>
                <span>dropped {state.notification.queue_dropped}</span>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                {state.notification.last_error_code
                  ? `마지막 실패 ${state.notification.last_error_code} · ${state.notification.last_failure_at ? formatTime(state.notification.last_failure_at) : "시각 없음"}`
                  : state.notification.last_success_at
                    ? `마지막 성공 ${formatTime(state.notification.last_success_at)}`
                    : "아직 전송 이력이 없습니다."}
              </p>
            </div>
          </div>
        </ConsoleSection>

        {state.provider !== "unavailable" ? (
          <ConsoleSection label="외부 보호 전환" title="Cloudflare transaction" description={`read-back stage: ${state.provider}${state.provider_drain_deadline_unix_seconds == null ? "" : ` · origin lock 예정 ${formatTime(state.provider_drain_deadline_unix_seconds * 1_000)}`}`}>
            <div className="grid gap-5 lg:grid-cols-[1fr_auto] lg:items-center">
              <div className="h-2 max-w-2xl overflow-hidden rounded-full bg-muted" aria-label={`Provider 진행률 ${providerProgress(state.provider)}%`}>
                <div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${providerProgress(state.provider)}%` }} />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="destructive" onClick={() => void runAction("/api/v1/actions/emergency-proxy")}><CloudCog className="size-3.5" /> 비상 보호</Button>
                <Button variant="outline" onClick={() => void runAction("/api/v1/actions/provider-restore")}><RotateCcw className="size-3.5" /> {state.mode === "RECOVERY_READY" ? "보호 해제 승인" : "긴급 Snapshot 복구"}</Button>
              </div>
            </div>
          </ConsoleSection>
        ) : null}
      </div>
    </>
  );
}

function SecurityRow({ label, value, healthy }: { label: string; value: string; healthy: boolean }) {
  return <div className="flex items-center justify-between gap-4"><dt className="text-muted-foreground">{label}</dt><dd className="flex items-center gap-2 font-mono text-[11px]"><span className={`size-1.5 rounded-full ${healthy ? "bg-emerald-500" : "bg-amber-500"}`} />{value}</dd></div>;
}

function serviceDot(state: string): string {
  if (["live", "valid", "complete", "healthy"].includes(state)) return "size-1.5 rounded-full bg-emerald-500";
  if (["unavailable", "disabled"].includes(state)) return "size-1.5 rounded-full bg-muted-foreground";
  return "size-1.5 rounded-full bg-amber-500";
}

function providerProgress(stage: string): number {
  return { ready: 0, pending: 5, snapshotted: 20, proxy_requested: 40, proxy_verified: 55, proxy_drain: 70, origin_lock_requested: 85, running: 90, complete: 100, restored: 100 }[stage] ?? 0;
}

function CompactMetric({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-r px-5 py-4 last:border-r-0 xl:border-b-0"><dt className="text-[11px] text-muted-foreground">{label}</dt><dd className="mt-1 font-mono text-sm">{value}</dd></div>;
}

function StatusSegment({ label, value, total, className }: { label: string; value: number; total: number; className: string }) {
  const weight = Math.max(1, percent(value, total));
  return <span className={`grid min-w-[58px] place-items-center text-white transition-[flex-grow] ${className}`} style={{ flexGrow: weight }}>{label} {value}</span>;
}
