import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { DataTable } from "../components/data-table";
import { ErrorState, LoadingState } from "../components/query-state";
import { SectionHeading } from "../components/section-heading";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
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
      <div className="mb-5 grid gap-3 md:grid-cols-[minmax(0,1fr)_160px_160px]">
        <label className="grid gap-1 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
          Client 검색
          <input
            value={search}
            onChange={(event) => { setSearch(event.target.value); setPage(0); }}
            placeholder="IP 또는 network"
            className="h-10 border border-zinc-700 bg-zinc-950 px-3 text-sm normal-case tracking-normal text-zinc-100 outline-none focus:border-orange-500"
          />
        </label>
        <label className="grid gap-1 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
          판정 필터
          <select
            value={filter}
            onChange={(event) => { setFilter(event.target.value as ClientFilter); setPage(0); }}
            className="h-10 border border-zinc-700 bg-zinc-950 px-3 text-sm normal-case tracking-normal text-zinc-100"
          >
            <option value="all">전체</option>
            <option value="throttled">제한 발생</option>
            <option value="denied">거부 발생</option>
          </select>
        </label>
        <label className="grid gap-1 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
          정렬
          <select
            value={sort}
            onChange={(event) => { setSort(event.target.value as ClientSort); setPage(0); }}
            className="h-10 border border-zinc-700 bg-zinc-950 px-3 text-sm normal-case tracking-normal text-zinc-100"
          >
            <option value="requests">요청 많은 순</option>
            <option value="bytes">전송량 순</option>
            <option value="recent">최근 관측 순</option>
          </select>
        </label>
      </div>
      <DataTable headers={["Client IP", "요청", "전송 body", "제한", "거부", "마지막 관측"]} empty={visible.length === 0}>
        {visible.map((client, index) => (
          <tr key={`${client.client_ip}:${currentPage * PAGE_SIZE + index}`} className="hover:bg-zinc-900/70">
            <td className="px-3 py-3 font-mono text-zinc-200">{client.client_ip}</td>
            <td className="px-3 py-3 font-mono">{client.requests.toLocaleString()}</td>
            <td className="px-3 py-3 font-mono text-zinc-500">{formatBytes(client.request_body_bytes + client.response_body_bytes)}</td>
            <td className="px-3 py-3"><Badge variant={client.throttled ? "warning" : "neutral"}>{client.throttled}</Badge></td>
            <td className="px-3 py-3"><Badge variant={client.denied ? "danger" : "neutral"}>{client.denied}</Badge></td>
            <td className="px-3 py-3 text-zinc-500">{formatTime(client.last_seen_unix_ms)}</td>
          </tr>
        ))}
      </DataTable>
      <div className="mt-4 flex items-center justify-between gap-4 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
        <span>{clients.length.toLocaleString()} clients · {currentPage + 1}/{pageCount}</span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</Button>
          <Button variant="outline" size="sm" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>다음</Button>
        </div>
      </div>
    </>
  );
}
