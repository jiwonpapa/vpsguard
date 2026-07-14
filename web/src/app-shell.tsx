import { useEffect, useState } from "react";
import { Link, Outlet } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BookOpenCheck,
  CircleDot,
  Cpu,
  KeyRound,
  Moon,
  Network,
  Route,
  ShieldCheck,
  Sun,
  Users,
} from "lucide-react";

import { useAuth } from "./auth";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { cn } from "./lib/utils";

const navigation = [
  ["/", "개요", ShieldCheck],
  ["/traffic", "트래픽", Activity],
  ["/clients", "클라이언트", Users],
  ["/routes", "경로", Route],
  ["/incidents", "사건", BookOpenCheck],
  ["/resources", "자원", Cpu],
] as const;

export function AppShell() {
  const queryClient = useQueryClient();
  const { openLogin } = useAuth();
  const [connected, setConnected] = useState(false);
  const [dark, setDark] = useState(true);

  useEffect(() => {
    const source = new EventSource("/api/v1/events");
    source.onopen = () => setConnected(true);
    source.onmessage = () => void queryClient.invalidateQueries();
    source.addEventListener("guard.mode_transition", () => void queryClient.invalidateQueries());
    source.addEventListener("operator.action", () => void queryClient.invalidateQueries());
    source.onerror = () => setConnected(false);
    return () => source.close();
  }, [queryClient]);

  const toggleTheme = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 selection:bg-orange-500 selection:text-zinc-950">
      <header className="sticky top-0 z-40 flex h-14 items-center border-b border-zinc-800 bg-zinc-950/95 px-4 backdrop-blur md:px-6">
        <Link to="/" className="flex min-w-48 items-center gap-3" aria-label="VPSGuard 개요">
          <span className="grid size-8 place-items-center bg-orange-500 font-mono text-xs font-black text-zinc-950">VG</span>
          <span className="font-semibold tracking-tight">VPSGuard</span>
          <Badge>MVP</Badge>
        </Link>
        <div className="ml-auto flex items-center gap-2">
          <div className="hidden items-center gap-2 pr-2 text-xs text-zinc-500 sm:flex">
            <CircleDot className={cn("size-3", connected ? "text-emerald-400" : "text-amber-400")} />
            {connected ? "SSE 연결됨" : "재연결 중"}
          </div>
          <Button variant="ghost" size="icon" onClick={openLogin} aria-label="운영 session 로그인">
            <KeyRound className="size-4" />
          </Button>
          <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label="테마 전환">
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
        </div>
      </header>
      <div className="grid min-h-[calc(100vh-3.5rem)] grid-cols-1 md:grid-cols-[190px_minmax(0,1fr)] xl:grid-cols-[190px_minmax(0,1fr)_250px]">
        <nav className="fixed inset-x-0 bottom-0 z-40 flex h-14 border-t border-zinc-800 bg-zinc-950 md:static md:h-auto md:flex-col md:border-r md:border-t-0 md:px-3 md:py-6" aria-label="주요 메뉴">
          {navigation.map(([to, label, Icon]) => (
            <Link
              key={to}
              to={to}
              activeOptions={{ exact: to === "/" }}
              aria-label={label}
              className="flex flex-1 items-center justify-center gap-3 border-l-2 border-transparent px-3 py-3 text-xs text-zinc-500 transition-colors hover:text-zinc-100 md:flex-none md:justify-start"
              activeProps={{ className: "border-orange-500 bg-zinc-900 text-zinc-50" }}
            >
              <Icon className="size-4 shrink-0" aria-hidden="true" />
              <span className="hidden md:inline">{label}</span>
            </Link>
          ))}
        </nav>
        <main className="min-w-0 px-4 py-7 pb-20 md:px-8 md:py-10 xl:px-10">
          <Outlet />
        </main>
        <aside className="hidden border-l border-zinc-800 bg-zinc-900/35 p-6 xl:block">
          <Network className="size-5 text-orange-400" aria-hidden="true" />
          <h2 className="mt-5 text-sm font-semibold">운영 경계</h2>
          <ul className="mt-4 divide-y divide-zinc-800 text-xs leading-5 text-zinc-500">
            <li className="py-3">UI와 Control API는 loopback 전용입니다.</li>
            <li className="py-3">Edge는 Control 장애 중에도 마지막 정상 정책으로 동작합니다.</li>
            <li className="py-3">Provider 전환은 검증 가능한 transaction으로만 수행합니다.</li>
            <li className="py-3">쓰기 명령은 session, CSRF, idempotency key가 필요합니다.</li>
          </ul>
          <div className="mt-8 border-t border-zinc-800 pt-5 font-mono text-[10px] uppercase tracking-widest text-zinc-600">
            Rust · Pingora · SQLite WAL
          </div>
        </aside>
      </div>
    </div>
  );
}
