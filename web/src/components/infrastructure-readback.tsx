import type { FirewallStatus, StatusResponse } from "../lib/types";
import { formatTime } from "../lib/utils";
import { ConsoleSection } from "./console-section";
import { Badge } from "./ui/badge";

export function InfrastructureReadback({
  status,
  firewall,
  firewallPending,
  firewallFailed,
}: {
  status: StatusResponse;
  firewall: FirewallStatus | undefined;
  firewallPending: boolean;
  firewallFailed: boolean;
}) {
  const tls = status.tls_management;
  const firewallLabel = firewallFailed
    ? "read-back 실패"
    : firewallPending
      ? "조회 중"
      : firewall?.snapshot?.active
        ? "active"
        : firewall?.mode === "disabled"
          ? "disabled"
          : "inactive";
  return (
    <ConsoleSection
      label="인프라 실제 상태"
      title="외부 보호·방화벽·TLS read-back"
      description="설정 의도가 아니라 각 소유 계층이 마지막으로 확인한 실제 상태입니다."
      contentClassName="p-0 sm:p-0"
    >
      <div className="grid divide-y lg:grid-cols-3 lg:divide-x lg:divide-y-0">
        <ReadbackCard
          label="Cloudflare"
          status={status.provider === "unavailable" ? "미설정" : status.provider}
          healthy={status.provider !== "failed"}
          lines={[
            `mode ${status.mode}`,
            status.provider_drain_deadline_unix_seconds == null
              ? "drain deadline 없음"
              : `drain ${formatTime(status.provider_drain_deadline_unix_seconds * 1_000)}`,
          ]}
        />
        <ReadbackCard
          label="Host firewall"
          status={firewallLabel}
          healthy={!firewallFailed && (firewall?.snapshot?.active === true || firewall?.mode === "disabled")}
          lines={[
            `owner ${firewall?.mode ?? "unavailable"}`,
            `backend ${firewall?.backend ?? "unavailable"}`,
            firewall?.snapshot
              ? `rules ${firewall.snapshot.owned_rules.length} owned / ${firewall.snapshot.foreign_rules.length} preserved`
              : "snapshot unavailable",
            firewall?.snapshot ? `fingerprint ${firewall.snapshot.fingerprint.slice(0, 12)}` : "",
          ]}
        />
        <ReadbackCard
          label="TLS lifecycle"
          status={tls.health}
          healthy={tls.health === "valid" && tls.renewal === "healthy"}
          lines={[
            `owner ${tls.ownership}`,
            `manager ${tls.manager ?? "unavailable"}`,
            `certificates ${tls.certificate_count}`,
            tls.earliest_expiry ? `expires ${formatTime(tls.earliest_expiry)}` : "expiry unavailable",
          ]}
        />
      </div>
    </ConsoleSection>
  );
}

function ReadbackCard({
  label,
  status,
  healthy,
  lines,
}: {
  label: string;
  status: string;
  healthy: boolean;
  lines: string[];
}) {
  return (
    <article className="min-w-0 px-5 py-5 sm:px-6" aria-label={`${label} read-back`}>
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</h3>
        <Badge variant={healthy ? "live" : "warning"}>{status}</Badge>
      </div>
      <div className="mt-4 space-y-1.5 font-mono text-[10px] text-muted-foreground">
        {lines.filter(Boolean).map((line) => <p key={line} className="truncate">{line}</p>)}
      </div>
    </article>
  );
}
