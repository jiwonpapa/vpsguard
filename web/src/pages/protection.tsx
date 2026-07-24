import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";

import { useAuth } from "../auth";
import { ConsoleSection } from "../components/console-section";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { api, apiErrorMessage } from "../lib/api";
import type {
  ProtectionPlan,
  ProtectionSettings,
} from "../lib/types";

const fields: Array<{
  key: keyof ProtectionSettings;
  label: string;
  description: string;
}> = [
  {
    key: "watch_strict_requests_per_minute",
    label: "WATCH strict",
    description: "관찰·회복 단계의 고비용 경로 한도",
  },
  {
    key: "local_strict_requests_per_minute",
    label: "LOCAL strict",
    description: "로컬 방어 단계의 고비용 경로 한도",
  },
  {
    key: "local_upload_requests_per_minute",
    label: "LOCAL upload",
    description: "로컬 방어 단계의 업로드 경로 한도",
  },
  {
    key: "emergency_strict_requests_per_minute",
    label: "EMERGENCY strict",
    description: "비상 보호 단계의 고비용 경로 한도",
  },
  {
    key: "emergency_upload_requests_per_minute",
    label: "EMERGENCY upload",
    description: "비상 보호 단계의 업로드 경로 한도",
  },
];

export function ProtectionPage() {
  const { capabilities } = useAuth();
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["protection-settings"],
    queryFn: api.protection,
    refetchInterval: 5_000,
  });
  const [draft, setDraft] = useState<ProtectionSettings | null>(null);
  const [loadedFingerprint, setLoadedFingerprint] = useState("");
  const [plan, setPlan] = useState<ProtectionPlan | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (status.data && status.data.fingerprint !== loadedFingerprint) {
      setDraft(status.data.settings);
      setLoadedFingerprint(status.data.fingerprint);
      setPlan(null);
    }
  }, [loadedFingerprint, status.data]);

  const planner = useMutation({
    mutationFn: api.protectionPlan,
    onSuccess: (value) => {
      setPlan(value);
      setMessage(
        value.changes.length
          ? "검증된 변경 계획을 만들었습니다. diff를 확인한 뒤 적용하십시오."
          : "현재 설정과 같아 적용할 변경이 없습니다.",
      );
    },
    onError: (error) => {
      setPlan(null);
      setMessage(apiErrorMessage(error, "보호 설정 계획을 만들지 못했습니다."));
    },
  });
  const applier = useMutation({
    mutationFn: api.protectionApply,
    onSuccess: async (value) => {
      setPlan(null);
      setMessage(
        value.applied
          ? `policy v${value.policy_version} 원자 적용을 완료했습니다. Edge read-back을 확인합니다.`
          : `동일 요청입니다. policy v${value.policy_version}을 유지했습니다.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["protection-settings"] });
    },
    onError: (error) => {
      setMessage(apiErrorMessage(error, "보호 설정을 적용하지 못했습니다."));
      void queryClient.invalidateQueries({ queryKey: ["protection-settings"] });
    },
  });

  if (status.isPending) return <LoadingState />;
  if (status.error) {
    return <ErrorState message="보호 설정과 Edge read-back 상태를 읽지 못했습니다." />;
  }
  if (!draft) return <LoadingState />;

  const current = status.data;
  const update = (key: keyof ProtectionSettings, raw: string) => {
    const value = Number(raw);
    setDraft((previous) => previous ? { ...previous, [key]: value } : previous);
    setPlan(null);
    setMessage("");
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    planner.mutate(draft);
  };

  return (
    <>
      <SectionHeading
        eyebrow="Hot policy controls"
        title="보호 정책"
        description="서비스를 재시작하지 않고 WATCH·LOCAL·EMERGENCY 경로 제한만 변경합니다. listener, origin, TLS와 비밀값은 이 화면에서 다루지 않습니다."
      />
      <div className="space-y-6">
        <ConsoleSection
          label="보호 정책 적용 상태"
          title="Control 적용과 Edge 관측"
          description="파일에 원자 적용된 version과 Edge telemetry에서 실제 관측한 version을 분리해 표시합니다."
        >
          <dl className="grid gap-5 sm:grid-cols-3">
            <State label="Control policy" value={`v${current.policy_version}`} />
            <State
              label="Edge observed"
              value={current.edge_observed_policy_version == null
                ? "미관측"
                : `v${current.edge_observed_policy_version}`}
            />
            <div>
              <dt className="text-xs text-muted-foreground">Read-back</dt>
              <dd className="mt-2">
                <Badge variant={current.edge_readback === "observed" ? "live" : "warning"}>
                  {readbackLabel(current.edge_readback)}
                </Badge>
              </dd>
            </div>
          </dl>
        </ConsoleSection>

        {!current.enforcement_active ? (
          <Alert className="border-amber-800/70 bg-amber-950/20 text-amber-300">
            <ShieldAlert className="size-5 text-amber-400" aria-hidden="true" />
            <AlertTitle>현재 자동 차단은 observe mode입니다.</AlertTitle>
            <AlertDescription>
              설정과 policy version은 보존되지만 자동 LOCAL·EMERGENCY 전환에 의한 동적 제한은 활성화되지 않습니다.
            </AlertDescription>
          </Alert>
        ) : null}

        {!capabilities.operate ? (
          <Alert className="border-amber-800/70 bg-amber-950/20 text-amber-300">
            <ShieldAlert className="size-5 text-amber-400" aria-hidden="true" />
            <AlertTitle>현재 계정은 보호 정책을 변경할 수 없습니다.</AlertTitle>
            <AlertDescription>
              적용 상태와 현재 한도는 볼 수 있지만 변경 계획과 적용은 운영 역할에만 허용됩니다.
            </AlertDescription>
          </Alert>
        ) : null}

        <div className="grid items-start gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <ConsoleSection
            label="단계별 경로 제한 설정"
            title="분당 요청 한도"
            description="1~6000 범위이며 WATCH ≥ LOCAL ≥ EMERGENCY, 같은 단계에서는 strict ≥ upload 관계를 강제합니다."
          >
            <form className="grid gap-5" onSubmit={submit}>
              <div className="grid gap-4 sm:grid-cols-2">
                {fields.map((field) => (
                  <div className="grid gap-2" key={field.key}>
                    <Label htmlFor={field.key}>{field.label}</Label>
                    <Input
                      id={field.key}
                      aria-describedby={`${field.key}-description`}
                      type="number"
                      min="1"
                      max="6000"
                      step="1"
                      required
                      disabled={!capabilities.operate}
                      value={draft[field.key]}
                      onChange={(event) => update(field.key, event.target.value)}
                    />
                    <p
                      id={`${field.key}-description`}
                      className="text-[11px] leading-4 text-muted-foreground"
                    >
                      {field.description}
                    </p>
                  </div>
                ))}
              </div>
              {capabilities.operate ? <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={planner.isPending || applier.isPending}>
                  {planner.isPending ? "검증 중" : "변경 계획 만들기"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setDraft(current.settings);
                    setPlan(null);
                    setMessage("");
                  }}
                >
                  현재값 복원
                </Button>
              </div> : null}
            </form>
            {message ? (
              <p className="mt-4 whitespace-pre-line text-xs leading-5 text-primary" aria-live="polite">
                {message}
              </p>
            ) : null}
          </ConsoleSection>

          <ConsoleSection
            label="보호 정책 변경 계획"
            title="검증된 diff"
            description="plan 생성 뒤 다른 변경이 먼저 적용되면 stale plan으로 거부합니다."
          >
            {plan && capabilities.operate ? (
              <>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="size-4 text-emerald-400" aria-hidden="true" />
                  <span className="text-sm font-semibold">
                    v{plan.current_policy_version} → v{plan.next_policy_version}
                  </span>
                </div>
                {plan.changes.length ? (
                  <dl className="mt-5 divide-y rounded-lg border">
                    {plan.changes.map((change) => (
                      <div
                        className="grid grid-cols-[1fr_auto] gap-3 px-4 py-3 text-xs"
                        key={change.field}
                      >
                        <dt className="text-muted-foreground">{fieldLabel(change.field)}</dt>
                        <dd className="font-mono">
                          {change.before} → {change.after} rpm
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <p className="mt-5 text-xs text-muted-foreground">
                    현재 policy와 같은 값입니다.
                  </p>
                )}
                <div className="mt-5 flex gap-2">
                  <Button variant="ghost" onClick={() => setPlan(null)}>폐기</Button>
                  <Button
                    disabled={!plan.changes.length || applier.isPending}
                    onClick={() => applier.mutate(plan)}
                  >
                    {applier.isPending ? "적용·검증 중" : "확인 후 적용"}
                  </Button>
                </div>
              </>
            ) : (
              <p className="py-10 text-center text-xs text-muted-foreground">
                {capabilities.operate
                  ? "왼쪽에서 후보를 입력하고 변경 계획을 만드십시오."
                  : "현재 역할에는 보호 정책 변경 권한이 없습니다."}
              </p>
            )}
          </ConsoleSection>
        </div>
      </div>
    </>
  );
}

function State({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-2 font-mono text-sm text-foreground">{value}</dd>
    </div>
  );
}

function fieldLabel(field: keyof ProtectionSettings): string {
  return fields.find((entry) => entry.key === field)?.label ?? field;
}

function readbackLabel(state: "pending" | "observed" | "superseded"): string {
  if (state === "observed") return "Edge 반영 확인";
  if (state === "superseded") return "상위 version 관측";
  return "Edge 반영 대기";
}
