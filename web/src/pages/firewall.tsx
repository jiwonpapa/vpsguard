import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { ShieldCheck, ShieldOff } from "lucide-react";

import { useAuth } from "../auth";
import { ConsoleSection } from "../components/console-section";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { api, apiErrorMessage } from "../lib/api";
import type { PendingFirewallPlan, UfwAction, UfwProtocol, UfwRule } from "../lib/types";

export function FirewallPage() {
  const { capabilities } = useAuth();
  const queryClient = useQueryClient();
  const status = useQuery({ queryKey: ["firewall"], queryFn: api.firewall, refetchInterval: 10_000 });
  const [plan, setPlan] = useState<PendingFirewallPlan | null>(null);
  const [message, setMessage] = useState("");
  const [ruleId, setRuleId] = useState("public_https");
  const [action, setAction] = useState<UfwAction>("allow");
  const [source, setSource] = useState("");
  const [port, setPort] = useState("443");
  const [protocol, setProtocol] = useState<UfwProtocol>("tcp");

  const planner = useMutation({
    mutationFn: api.firewallPlan,
    onSuccess: (value) => {
      setPlan(value);
      setMessage("변경 계획을 만들었습니다. 적용 전 내용을 확인하십시오.");
    },
    onError: (error) => setMessage(apiErrorMessage(error, "방화벽 계획을 만들지 못했습니다.")),
  });
  const applier = useMutation({
    mutationFn: api.firewallApply,
    onSuccess: async () => {
      setPlan(null);
      setMessage("UFW 적용과 read-back 검증을 완료했습니다.");
      await queryClient.invalidateQueries({ queryKey: ["firewall"] });
    },
    onError: (error) => setMessage(apiErrorMessage(error, "방화벽 변경을 적용하지 못했습니다.")),
  });

  if (status.isPending) return <LoadingState />;
  if (status.error) return <ErrorState message="방화벽 상태를 읽지 못했습니다. 권한 helper와 UFW 상태를 확인하십시오." />;

  const state = status.data;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setMessage("");
    const destinationPort = port.trim() ? Number(port) : null;
    const rule: UfwRule = {
      id: ruleId.trim(),
      action,
      source: source.trim() || null,
      destination_port: destinationPort,
      protocol,
    };
    planner.mutate({ kind: "add", rule });
  };

  return (
    <>
      <SectionHeading
        eyebrow="Host firewall ownership"
        title="UFW 방화벽"
        description="독립 설치에서는 VPSGuard 소유 rule만 변경하며, JW-agent 연동에서는 읽기 전용으로 소유권을 위임합니다."
      />
      <div className="space-y-6">
        <ConsoleSection label="방화벽 소유권과 상태" title="소유권과 현재 상태" description="기존 rule을 보존하면서 VPSGuard 소유 범위만 명시적으로 관리합니다.">
          <dl className="grid gap-5 md:grid-cols-3">
            <State label="운영 모드" value={state.mode} />
            <State label="Backend" value={state.backend} />
            <div>
              <dt className="text-xs text-muted-foreground">변경 권한</dt>
              <dd><Badge className="mt-2" variant={state.mutable ? "live" : "warning"}>{state.mutable ? "VPSGuard 소유" : "외부 위임"}</Badge></dd>
            </div>
          </dl>
        </ConsoleSection>

        {!state.mutable || !capabilities.operate ? (
          <Alert className="border-amber-800/70 bg-amber-950/20 text-amber-300">
            <ShieldOff className="size-5 text-amber-400" aria-hidden="true" />
            <AlertTitle>이 설치에서는 UFW를 변경하지 않습니다.</AlertTitle>
            <AlertDescription>
              {!capabilities.operate
                ? "현재 계정은 읽기 전용 역할입니다. UFW 상태는 볼 수 있지만 변경 계획과 적용은 허용되지 않습니다."
                : state.mode === "jw_agent_delegated"
                ? "JW-agent가 host firewall의 단일 소유자입니다. 충돌 방지를 위해 VPSGuard 변경 API가 닫혀 있습니다."
                : "설정에서 firewall.mode를 standalone_ufw로 명시해야 UFW 관리가 열립니다."}
            </AlertDescription>
          </Alert>
        ) : null}

        <div className={`grid items-start gap-6 ${state.mutable && capabilities.operate ? "xl:grid-cols-2" : ""}`}>
          {state.mutable && capabilities.operate ? (
            <ConsoleSection label="새 규칙 계획" title="새 inbound rule 계획" description="UFW는 자동 활성화하지 않으며 SSH 포트 deny와 무제한 catch-all deny를 거부합니다.">
              <form className="mt-5 grid gap-4" onSubmit={submit}>
                <Field id="firewall-rule-id" label="Rule ID"><Input id="firewall-rule-id" value={ruleId} onChange={(event) => setRuleId(event.target.value)} pattern="[A-Za-z0-9_-]{1,48}" required /></Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field id="firewall-action" label="동작"><Select value={action} onValueChange={(value) => setAction(value as UfwAction)}><SelectTrigger id="firewall-action" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="allow">허용</SelectItem><SelectItem value="deny">차단</SelectItem></SelectContent></Select></Field>
                  <Field id="firewall-protocol" label="Protocol"><Select value={protocol} onValueChange={(value) => setProtocol(value as UfwProtocol)}><SelectTrigger id="firewall-protocol" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="tcp">TCP</SelectItem><SelectItem value="udp">UDP</SelectItem><SelectItem value="any">ANY</SelectItem></SelectContent></Select></Field>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Field id="firewall-source" label="Source IP/CIDR (선택)"><Input id="firewall-source" value={source} onChange={(event) => setSource(event.target.value)} placeholder="203.0.113.0/24" /></Field>
                  <Field id="firewall-port" label="Port (선택)"><Input id="firewall-port" value={port} onChange={(event) => setPort(event.target.value)} type="number" min="1" max="65535" /></Field>
                </div>
                <Button disabled={planner.isPending || applier.isPending} type="submit">{planner.isPending ? "검증 중" : "계획 만들기"}</Button>
              </form>
              {message ? <p className="mt-4 whitespace-pre-line text-xs leading-5 text-primary" aria-live="polite">{message}</p> : null}
            </ConsoleSection>
          ) : null}

          <ConsoleSection label="VPSGuard 소유 규칙" title="현재 VPSGuard 소유 rule" description="외부 rule은 변경하지 않고 아래 소유 rule만 plan/apply 합니다.">
            <div className="divide-y rounded-lg border">
              {state.snapshot?.owned_rules.length ? state.snapshot.owned_rules.map((rule) => (
                <div key={`${rule.number}-${rule.id}`} className="px-4 py-3">
                  <div className="font-mono text-xs text-foreground">#{rule.number} {rule.id}</div>
                  <div className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{rule.summary}</div>
                </div>
              )) : <p className="px-4 py-8 text-center text-xs text-muted-foreground">VPSGuard 소유 rule이 없습니다.</p>}
            </div>
            <p className="mt-3 font-mono text-[10px] text-muted-foreground">foreign rules preserved {state.snapshot?.foreign_rules.length ?? 0}</p>

            {plan && capabilities.operate ? (
              <div className="mt-7 rounded-lg border border-primary/40 bg-primary/5 p-5">
                <ShieldCheck className="size-5 text-orange-400" aria-hidden="true" />
                <h3 className="mt-3 text-sm font-semibold">승인 대기 계획</h3>
                <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                  <State label="동작" value={`${plan.plan.mutation.kind} ${plan.plan.mutation.rule.action}`} />
                  <State label="대상" value={`${plan.plan.mutation.rule.source ?? "모든 source"} → ${plan.plan.mutation.rule.destination_port ?? "모든 port"}/${plan.plan.mutation.rule.protocol}`} />
                  <State label="SSH 보호 포트" value={String(plan.plan.ssh_port)} />
                  <State label="Snapshot" value={plan.plan.before_fingerprint.slice(0, 12)} />
                </dl>
                <div className="mt-5 flex gap-2">
                  <Button variant="ghost" onClick={() => setPlan(null)}>폐기</Button>
                  <Button disabled={applier.isPending} onClick={() => applier.mutate(plan.operation_id)}>{applier.isPending ? "적용·검증 중" : "확인 후 적용"}</Button>
                </div>
              </div>
            ) : null}
          </ConsoleSection>
        </div>
      </div>
    </>
  );
}

function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return <div className="grid gap-2"><Label htmlFor={id} className="text-xs text-muted-foreground">{label}</Label>{children}</div>;
}

function State({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-2 break-all font-mono text-sm text-foreground">{value}</dd></div>;
}
