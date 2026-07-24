import { useEffect, useState, type ReactNode } from "react";
import { Link, Outlet } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BookOpenCheck,
  BookText,
  CircleDot,
  Cpu,
  KeyRound,
  LockKeyhole,
  LogOut,
  Menu,
  Moon,
  Route,
  SlidersHorizontal,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  Sun,
  Users,
} from "lucide-react";

import { useAuth } from "./auth";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { LoadingState } from "./components/query-state";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "./components/ui/dialog";
import { Tooltip, TooltipContent, TooltipTrigger } from "./components/ui/tooltip";
import { cn } from "./lib/utils";

const navigation = [
  {
    label: "모니터링",
    items: [
      ["/", "개요", ShieldCheck],
      ["/traffic", "트래픽", Activity],
      ["/clients", "클라이언트", Users],
      ["/routes", "경로", Route],
    ],
  },
  {
    label: "운영",
    items: [
      ["/incidents", "사건", BookOpenCheck],
      ["/resources", "자원", Cpu],
      ["/protection", "보호 정책", SlidersHorizontal],
      ["/firewall", "방화벽", ShieldEllipsis],
      ["/glossary", "용어집", BookText],
    ],
  },
] as const;

export function AppShell() {
  const queryClient = useQueryClient();
  const { ready, authenticated, actor, role, capabilities, logout, openLogin, revokeAll } = useAuth();
  const [connected, setConnected] = useState(false);
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));

  useEffect(() => {
    if (!ready || !authenticated) {
      setConnected(false);
      return;
    }
    const source = new EventSource("/api/v1/events");
    source.onopen = () => setConnected(true);
    source.onmessage = () => void queryClient.invalidateQueries();
    source.addEventListener("guard.mode_transition", () => void queryClient.invalidateQueries());
    source.addEventListener("operator.action", () => void queryClient.invalidateQueries());
    source.onerror = () => setConnected(false);
    return () => source.close();
  }, [authenticated, queryClient, ready]);

  const toggleTheme = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    window.localStorage.setItem("vpsguard-theme", next ? "dark" : "light");
  };

  const connectionLabel = !ready
    ? "인증 확인 중"
    : authenticated
      ? connected
        ? "실시간 연결"
        : "데이터 연결 대기"
      : "로그인 필요";

  return (
    <div className="min-h-screen bg-muted/25 text-foreground selection:bg-primary selection:text-primary-foreground">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <SidebarBrand />
        <SidebarNavigation onNavigate={() => undefined} />
        <div className="mt-auto border-t border-sidebar-border px-5 py-4">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <LockKeyhole className="size-3.5 text-primary" aria-hidden="true" />
            <span>관리 HTTPS 전용</span>
          </div>
          <p className="mt-2 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground/60">
            Rust · Pingora · SQLite WAL
          </p>
        </div>
      </aside>

      <div className="min-h-screen md:pl-60">
        <header className="sticky top-0 z-30 flex h-16 items-center border-b border-border/80 bg-background/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <Button
            variant="ghost"
            size="icon"
            className="mr-2 md:hidden"
            aria-label="주요 메뉴 열기"
            onClick={() => setMobileNavigationOpen(true)}
          >
            <Menu className="size-4" />
          </Button>
          <div className="md:hidden"><SidebarBrand compact /></div>
          <div className="flex items-center gap-2">
            <CircleDot
              className={cn("size-3", connected ? "text-emerald-500" : authenticated ? "text-amber-500" : "text-muted-foreground")}
              aria-hidden="true"
            />
            <span className="text-xs font-medium text-muted-foreground">{connectionLabel}</span>
          </div>
          <div className="ml-auto flex items-center gap-1">
            {authenticated ? (
              <>
                <div className="mr-2 hidden text-right lg:block">
                  <div className="text-xs font-medium">{actor}</div>
                  <div className="text-[10px] text-muted-foreground">{roleLabel(role)}</div>
                </div>
                {capabilities.administer ? (
                  <IconAction label="모든 관리자 session 로그아웃" onClick={revokeAll}><ShieldX className="size-4" /></IconAction>
                ) : null}
                <IconAction label={`${actor ?? "관리자"} 로그아웃`} onClick={() => void logout()}><LogOut className="size-4" /></IconAction>
              </>
            ) : (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={openLogin} aria-label="VPSGuard 관리자 로그인">
                    <KeyRound className="size-3.5" />
                    <span className="hidden sm:inline">관리자 로그인</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent sideOffset={6}>VPSGuard 관리자 로그인</TooltipContent>
              </Tooltip>
            )}
            <IconAction label="테마 전환" onClick={toggleTheme}>{dark ? <Sun className="size-4" /> : <Moon className="size-4" />}</IconAction>
          </div>
        </header>

        <main className="mx-auto min-w-0 max-w-[1480px] px-4 py-6 sm:px-6 sm:py-8 lg:px-8 lg:py-10">
          {!ready ? <LoadingState label="관리자 인증 확인 중" /> : authenticated ? <Outlet /> : <AccessGate onLogin={openLogin} />}
        </main>
      </div>

      <Dialog open={mobileNavigationOpen} onOpenChange={setMobileNavigationOpen}>
        <DialogContent
          className="!top-0 !left-0 h-dvh !max-w-72 !translate-x-0 !translate-y-0 content-start gap-0 rounded-none border-r bg-sidebar p-0"
          aria-label="모바일 주요 메뉴"
        >
          <DialogTitle className="sr-only">주요 메뉴</DialogTitle>
          <DialogDescription className="sr-only">VPSGuard 관리자 화면 이동</DialogDescription>
          <SidebarBrand />
          <SidebarNavigation onNavigate={() => setMobileNavigationOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  );
}

function roleLabel(role: ReturnType<typeof useAuth>["role"]): string {
  if (role === "viewer") return "조회자 · IP 마스킹";
  if (role === "analyst") return "분석자 · 민감 export";
  if (role === "operator") return "운영자 · 로컬 조치";
  if (role === "administrator") return "관리자 · 전체 권한";
  return "인증된 사용자";
}

function SidebarBrand({ compact = false }: { compact?: boolean }) {
  return (
    <Link
      to="/"
      className={cn("flex items-center gap-3", compact ? "h-10" : "h-16 border-b border-sidebar-border px-5")}
      aria-label="VPSGuard 개요"
    >
      <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground shadow-sm shadow-primary/20">
        <ShieldCheck className="size-4" aria-hidden="true" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-semibold tracking-tight">VPSGuard</span>
        {!compact ? <span className="block text-[10px] text-muted-foreground">Edge security console</span> : null}
      </span>
      {!compact ? <Badge variant="neutral" className="ml-auto">MVP</Badge> : null}
    </Link>
  );
}

function SidebarNavigation({ onNavigate }: { onNavigate: () => void }) {
  return (
    <nav className="flex-1 overflow-y-auto px-3 py-5" aria-label="주요 메뉴">
      {navigation.map((group, index) => (
        <div key={group.label} className={cn(index > 0 && "mt-7")}>
          <div className="px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground/65">{group.label}</div>
          <div className="mt-2 space-y-1">
            {group.items.map(([to, label, Icon]) => (
              <Link
                key={to}
                to={to}
                activeOptions={{ exact: to === "/" }}
                aria-label={label}
                onClick={onNavigate}
                className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                activeProps={{ className: "bg-sidebar-accent text-sidebar-accent-foreground shadow-sm" }}
              >
                <Icon className="size-4 shrink-0" aria-hidden="true" />
                <span>{label}</span>
                <span className="ml-auto hidden size-1.5 rounded-full bg-primary [[data-status=active]_&]:block" />
              </Link>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

function AccessGate({ onLogin }: { onLogin: () => void }) {
  return (
    <div className="grid min-h-[calc(100vh-9rem)] place-items-center py-8">
      <section className="w-full max-w-3xl overflow-hidden rounded-2xl border bg-card shadow-lg shadow-black/5" aria-labelledby="access-gate-title">
        <div className="grid md:grid-cols-[1.3fr_0.7fr]">
          <div className="p-7 sm:p-9">
            <span className="grid size-11 place-items-center rounded-xl bg-primary/10 text-primary">
              <KeyRound className="size-5" aria-hidden="true" />
            </span>
            <p className="mt-6 text-[10px] font-semibold uppercase tracking-[0.18em] text-primary">Restricted operations</p>
            <h1 id="access-gate-title" className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">관리자 로그인이 필요합니다</h1>
            <p className="mt-3 max-w-xl text-sm leading-6 text-muted-foreground">
              방어 상태와 운영 설정은 인증된 관리자에게만 표시됩니다. 서버 관리자 계정과 2단계 인증으로 접속하십시오.
            </p>
            <Button className="mt-7" onClick={onLogin}>
              <KeyRound className="size-4" aria-hidden="true" />
              VPSGuard 관리자 로그인
            </Button>
          </div>
          <div className="border-t bg-muted/40 p-7 md:border-t-0 md:border-l sm:p-9">
            <h2 className="text-sm font-semibold">보호된 관리 경로</h2>
            <ul className="mt-5 space-y-5 text-xs leading-5 text-muted-foreground">
              <li className="flex gap-3"><span className="mt-1 size-1.5 shrink-0 rounded-full bg-emerald-500" />HTTPS 관리 호스트에서만 접근합니다.</li>
              <li className="flex gap-3"><span className="mt-1 size-1.5 shrink-0 rounded-full bg-emerald-500" />비밀번호와 TOTP를 함께 검증합니다.</li>
              <li className="flex gap-3"><span className="mt-1 size-1.5 shrink-0 rounded-full bg-emerald-500" />쓰기 작업은 재인증과 감사 기록을 남깁니다.</li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}

function IconAction({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon" onClick={onClick} aria-label={label}>{children}</Button>
      </TooltipTrigger>
      <TooltipContent sideOffset={6}>{label}</TooltipContent>
    </Tooltip>
  );
}
