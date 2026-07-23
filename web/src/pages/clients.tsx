import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { DataTable } from "../components/data-table";
import { ConsoleSection } from "../components/console-section";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { api } from "../lib/api";
import { formatBytes, formatTime } from "../lib/utils";

const PAGE_SIZE = 50;
type ClientFilter = "all" | "throttled" | "denied";
type ClientSort = "requests" | "bytes" | "recent";

export function ClientsPage() {
  const query = useQuery({ queryKey: ["clients"], queryFn: api.clients, refetchInterval: 10_000 });
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<ClientFilter>("all");
  const [sort, setSort] = useState<ClientSort>("requests");
  const [page, setPage] = useState(0);
  const clients = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return [...(query.data ?? [])]
      .filter((client) => !needle || client.client_ip.toLowerCase().includes(needle))
      .filter((client) => filter === "all" || client[filter] > 0)
      .sort((left, right) => {
        if (sort === "bytes") {
          return (right.request_body_bytes + right.response_body_bytes) - (left.request_body_bytes + left.response_body_bytes);
        }
        if (sort === "recent") return right.last_seen_unix_ms - left.last_seen_unix_ms;
        return right.requests - left.requests;
      });
  }, [filter, query.data, search, sort]);
  if (query.isPending) return <LoadingState />;
  if (query.error) return <ErrorState message="Client aggregate를 읽지 못했습니다." />;
  const pageCount = Math.max(1, Math.ceil(clients.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visible = clients.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  return (
    <>
      <SectionHeading eyebrow="Client aggregates" title="외부 클라이언트" description="원본 IP는 보존기간과 인증 session 안에서만 표시하며, 기본 응답은 network 단위로 마스킹합니다." />
      <div className="space-y-6">
        <ConsoleSection label="클라이언트 필터" title="필터와 정렬" description="IP·판정·전송량 기준으로 과다 요청 주체를 좁힙니다.">
          <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_180px_180px]">
            <div className="grid gap-2">
              <Label htmlFor="client-search" className="text-xs text-muted-foreground">Client 검색</Label>
              <Input id="client-search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} placeholder="IP 또는 network" className="h-10 normal-case tracking-normal" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="client-filter" className="text-xs text-muted-foreground">판정 필터</Label>
              <Select value={filter} onValueChange={(value) => { setFilter(value as ClientFilter); setPage(0); }}>
                <SelectTrigger id="client-filter" className="h-10 w-full"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="all">전체</SelectItem><SelectItem value="throttled">제한 발생</SelectItem><SelectItem value="denied">거부 발생</SelectItem></SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="client-sort" className="text-xs text-muted-foreground">정렬</Label>
              <Select value={sort} onValueChange={(value) => { setSort(value as ClientSort); setPage(0); }}>
                <SelectTrigger id="client-sort" className="h-10 w-full"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="requests">요청 많은 순</SelectItem><SelectItem value="bytes">전송량 순</SelectItem><SelectItem value="recent">최근 관측 순</SelectItem></SelectContent>
              </Select>
            </div>
          </div>
        </ConsoleSection>

        <ConsoleSection
          label="클라이언트 목록"
          title="클라이언트 목록"
          description={`조건에 맞는 클라이언트 ${clients.length.toLocaleString()}개`}
          contentClassName="p-0 sm:p-0"
        >
          <DataTable headers={["Client IP", "요청", "전송 body", "제한", "거부", "마지막 관측"]} empty={visible.length === 0}>
            {visible.map((client, index) => (
              <tr key={`${client.client_ip}:${currentPage * PAGE_SIZE + index}`} className="transition-colors hover:bg-muted/35">
                <td className="px-4 py-3 font-mono text-foreground">{client.client_ip}</td>
                <td className="px-4 py-3 font-mono">{client.requests.toLocaleString()}</td>
                <td className="px-4 py-3 font-mono text-muted-foreground">{formatBytes(client.request_body_bytes + client.response_body_bytes)}</td>
                <td className="px-4 py-3"><Badge variant={client.throttled ? "warning" : "neutral"}>{client.throttled}</Badge></td>
                <td className="px-4 py-3"><Badge variant={client.denied ? "danger" : "neutral"}>{client.denied}</Badge></td>
                <td className="px-4 py-3 text-muted-foreground">{formatTime(client.last_seen_unix_ms)}</td>
              </tr>
            ))}
          </DataTable>
          <div className="flex items-center justify-between gap-4 border-t px-5 py-4 font-mono text-[10px] text-muted-foreground sm:px-6">
            <span>{clients.length.toLocaleString()} clients · {currentPage + 1}/{pageCount}</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</Button>
              <Button variant="outline" size="sm" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>다음</Button>
            </div>
          </div>
        </ConsoleSection>
      </div>
    </>
  );
}
