import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { ShieldCheck, ShieldOff } from "lucide-react";

import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { api, apiErrorMessage } from "../lib/api";
import type { PendingFirewallPlan, UfwAction, UfwProtocol, UfwRule } from "../lib/types";

export function FirewallPage() {
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
      <section className="mb-8 grid gap-4 border-y border-zinc-800 py-5 md:grid-cols-3">
        <State label="운영 모드" value={state.mode} />
        <State label="Backend" value={state.backend} />
        <div>
          <div className="text-xs text-zinc-500">변경 권한</div>
          <Badge className="mt-2" variant={state.mutable ? "live" : "warning"}>
            {state.mutable ? "VPSGuard 소유" : "외부 위임"}
          </Badge>
        </div>
      </section>

      {!state.mutable ? (
        <section className="border border-amber-800 bg-amber-950/20 p-5">
          <ShieldOff className="size-5 text-amber-400" aria-hidden="true" />
          <h2 className="mt-3 text-sm font-semibold">이 설치에서는 UFW를 변경하지 않습니다.</h2>
          <p className="mt-2 text-xs leading-5 text-zinc-400">
            {state.mode === "jw_agent_delegated"
              ? "JW-agent가 host firewall의 단일 소유자입니다. 충돌 방지를 위해 VPSGuard 변경 API가 닫혀 있습니다."
              : "설정에서 firewall.mode를 standalone_ufw로 명시해야 UFW 관리가 열립니다."}
          </p>
        </section>
      ) : (
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <section>
            <h2 className="text-sm font-semibold">새 inbound rule 계획</h2>
            <p className="mt-1 text-xs leading-5 text-zinc-500">UFW는 자동 활성화하지 않으며 SSH 포트 deny와 무제한 catch-all deny를 거부합니다.</p>
            <form className="mt-5 grid gap-4" onSubmit={submit}>
              <Field label="Rule ID"><input value={ruleId} onChange={(event) => setRuleId(event.target.value)} pattern="[A-Za-z0-9_-]{1,48}" required className={inputClass} /></Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="동작"><select value={action} onChange={(event) => setAction(event.target.value as UfwAction)} className={inputClass}><option value="allow">허용</option><option value="deny">차단</option></select></Field>
                <Field label="Protocol"><select value={protocol} onChange={(event) => setProtocol(event.target.value as UfwProtocol)} className={inputClass}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">ANY</option></select></Field>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Source IP/CIDR (선택)"><input value={source} onChange={(event) => setSource(event.target.value)} placeholder="203.0.113.0/24" className={inputClass} /></Field>
                <Field label="Port (선택)"><input value={port} onChange={(event) => setPort(event.target.value)} type="number" min="1" max="65535" className={inputClass} /></Field>
              </div>
              <Button disabled={planner.isPending || applier.isPending} type="submit">{planner.isPending ? "검증 중" : "계획 만들기"}</Button>
            </form>
            {message ? <p className="mt-4 whitespace-pre-line text-xs leading-5 text-orange-300" aria-live="polite">{message}</p> : null}
          </section>

          <section>
            <h2 className="text-sm font-semibold">현재 VPSGuard 소유 rule</h2>
            <div className="mt-4 divide-y divide-zinc-800 border-y border-zinc-800">
              {state.snapshot?.owned_rules.length ? state.snapshot.owned_rules.map((rule) => (
                <div key={`${rule.number}-${rule.id}`} className="py-3">
                  <div className="font-mono text-xs text-zinc-200">#{rule.number} {rule.id}</div>
                  <div className="mt-1 truncate font-mono text-[10px] text-zinc-600">{rule.summary}</div>
                </div>
              )) : <p className="py-4 text-xs text-zinc-500">VPSGuard 소유 rule이 없습니다.</p>}
            </div>
            <p className="mt-3 font-mono text-[10px] uppercase text-zinc-600">foreign rules preserved {state.snapshot?.foreign_rules.length ?? 0}</p>

            {plan ? (
              <div className="mt-7 border border-orange-800 bg-orange-950/20 p-5">
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
          </section>
        </div>
      )}
    </>
  );
}

const inputClass = "mt-2 h-10 w-full border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none focus:border-orange-500";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="block font-mono text-[10px] uppercase tracking-wider text-zinc-500">{label}{children}</label>;
}

function State({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-zinc-500">{label}</dt><dd className="mt-2 break-all font-mono text-sm text-zinc-200">{value}</dd></div>;
}
