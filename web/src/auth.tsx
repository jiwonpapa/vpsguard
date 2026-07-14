import { createContext, useContext, useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, X } from "lucide-react";

import { ApiError, createSession, performAction } from "./lib/api";
import { Button } from "./components/ui/button";

interface AuthContextValue {
  runAction: (path: string) => Promise<void>;
  openLogin: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState("");
  const [pendingPath, setPendingPath] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const execute = async (path: string) => {
    try {
      const result = await performAction(path);
      setMessage(`상태 변경 완료: ${result.mode}`);
      await queryClient.invalidateQueries();
    } catch (error) {
      if (error instanceof ApiError && error.code === "SESSION_REQUIRED") {
        setPendingPath(path);
        setOpen(true);
        return;
      }
      setMessage(error instanceof Error ? error.message : "운영 명령에 실패했습니다.");
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await createSession(token);
      setToken("");
      setOpen(false);
      if (pendingPath) {
        const path = pendingPath;
        setPendingPath(null);
        await execute(path);
      } else {
        setMessage("운영 session이 준비됐습니다.");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "로그인에 실패했습니다.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthContext.Provider value={{ runAction: execute, openLogin: () => setOpen(true) }}>
      {children}
      {open ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" role="presentation">
          <section
            className="w-full max-w-md border border-zinc-700 bg-zinc-950 p-6 shadow-2xl"
            role="dialog"
            aria-modal="true"
            aria-labelledby="session-title"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <KeyRound className="mb-4 size-5 text-orange-400" aria-hidden="true" />
                <h2 id="session-title" className="text-lg font-semibold">운영 session 시작</h2>
                <p className="mt-2 text-sm leading-6 text-zinc-500">
                  서버의 bootstrap token은 session 발급에만 사용하며 브라우저 저장소에 남기지 않습니다.
                </p>
              </div>
              <Button variant="ghost" size="icon" onClick={() => setOpen(false)} aria-label="닫기">
                <X className="size-4" />
              </Button>
            </div>
            <form className="mt-6" onSubmit={submit}>
              <label htmlFor="bootstrap-token" className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                VPS_GUARD_ACTION_TOKEN
              </label>
              <input
                id="bootstrap-token"
                type="password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                autoComplete="off"
                className="mt-2 h-10 w-full border border-zinc-700 bg-zinc-900 px-3 font-mono text-sm outline-none focus:border-orange-500"
                required
                autoFocus
              />
              <Button className="mt-4 w-full" disabled={busy} type="submit">
                {busy ? "검증 중" : "Session 발급"}
              </Button>
            </form>
          </section>
        </div>
      ) : null}
      {message ? (
        <button
          type="button"
          className="fixed bottom-5 right-5 z-50 border border-zinc-700 bg-zinc-100 px-4 py-3 text-left text-xs font-semibold text-zinc-950 shadow-xl"
          onClick={() => setMessage(null)}
        >
          {message}
        </button>
      ) : null}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider가 필요합니다.");
  return value;
}
