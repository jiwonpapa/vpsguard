import {
  createContext,
  useContext,
  useEffect,
  useState,
  type FormEvent,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, ShieldCheck, X } from "lucide-react";

import {
  ApiError,
  apiErrorMessage,
  confirmEnrollment,
  createBreakGlassSession,
  getAuthStatus,
  loginWithRecoveryCode,
  loginWithTotp,
  logoutSession,
  performAction,
  revokeAllSessions,
  restoreSession,
  startEnrollment,
  type AuthStatus,
  type EnrollmentStart,
  type SessionInfo,
} from "./lib/api";
import { Button } from "./components/ui/button";
import { validateAdminSetup } from "./lib/auth";

interface AuthContextValue {
  authenticated: boolean;
  actor: string | null;
  runAction: (path: string) => Promise<void>;
  openLogin: () => void;
  logout: () => Promise<void>;
  revokeAll: () => void;
}

type AuthView = "login" | "setup-account" | "setup-totp" | "recovery-codes" | "break-glass";

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [view, setView] = useState<AuthView>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [secondFactor, setSecondFactor] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [bootstrapCode, setBootstrapCode] = useState("");
  const [enrollment, setEnrollment] = useState<EnrollmentStart | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [pendingPath, setPendingPath] = useState<string | null>(null);
  const [confirmPath, setConfirmPath] = useState<string | null>(null);
  const [revokeAllOpen, setRevokeAllOpen] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void Promise.all([getAuthStatus(), restoreSession()])
      .then(([authStatus, restored]) => {
        setStatus(authStatus);
        setSession(restored);
        if (restored) void queryClient.invalidateQueries();
        if (authStatus.setup_required && !restored) {
          setView("setup-account");
          setOpen(true);
        }
      })
      .catch((error: unknown) => {
        setMessage(apiErrorMessage(error, "인증 상태를 확인하지 못했습니다."));
      });
  }, [queryClient]);

  const showLogin = () => {
    setMessage(null);
    setView(status?.setup_required ? "setup-account" : "login");
    setOpen(true);
  };

  const execute = async (path: string) => {
    try {
      const result = await performAction(path);
      setMessage(`상태 변경 완료: ${result.mode}`);
      await queryClient.invalidateQueries();
    } catch (error) {
      if (
        error instanceof ApiError &&
        (error.code === "SESSION_REQUIRED" || error.status === 401 || error.code === "CSRF_AUTH_REQUIRED")
      ) {
        setSession(null);
        setPendingPath(path);
        showLogin();
        return;
      }
      setMessage(apiErrorMessage(error, "운영 명령에 실패했습니다."));
    }
  };

  const finishLogin = async (nextSession: SessionInfo) => {
    setSession(nextSession);
    setPassword("");
    setSecondFactor("");
    setBootstrapCode("");
    setOpen(false);
    await queryClient.invalidateQueries();
    if (pendingPath) {
      const path = pendingPath;
      setPendingPath(null);
      await execute(path);
    } else {
      setMessage(`${nextSession.actor} 관리자로 로그인했습니다.`);
    }
  };

  const submitLogin = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const nextSession = useRecovery
        ? await loginWithRecoveryCode(username, password, secondFactor)
        : await loginWithTotp(username, password, secondFactor);
      await finishLogin(nextSession);
    } catch (error) {
      setMessage(apiErrorMessage(error, "로그인에 실패했습니다."));
    } finally {
      setBusy(false);
    }
  };

  const submitSetupAccount = async (event: FormEvent) => {
    event.preventDefault();
    const validationError = validateAdminSetup(username, password, passwordConfirm);
    if (validationError) {
      setMessage(validationError);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const started = await startEnrollment(bootstrapCode, username, password);
      setEnrollment(started);
      setBootstrapCode("");
      setPassword("");
      setPasswordConfirm("");
      setView("setup-totp");
    } catch (error) {
      setMessage(apiErrorMessage(error, "관리자 등록을 시작하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  };

  const submitSetupTotp = async (event: FormEvent) => {
    event.preventDefault();
    if (!enrollment) return;
    setBusy(true);
    setMessage(null);
    try {
      const complete = await confirmEnrollment(enrollment.enrollment_id, secondFactor);
      setSession(complete.session);
      setRecoveryCodes(complete.recovery_codes);
      setSecondFactor("");
      setStatus((current) => current ? { ...current, setup_required: false, password_login_enabled: true, totp_required: true } : current);
      setView("recovery-codes");
      await queryClient.invalidateQueries();
    } catch (error) {
      setMessage(apiErrorMessage(error, "2단계 인증을 확인하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  };

  const submitBreakGlass = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await finishLogin(await createBreakGlassSession(bootstrapCode));
    } catch (error) {
      setMessage(apiErrorMessage(error, "긴급 복구 로그인에 실패했습니다."));
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    try {
      await logoutSession();
      setSession(null);
      await queryClient.invalidateQueries();
      setMessage("현재 관리자 session에서 로그아웃했습니다.");
    } catch (error) {
      setMessage(apiErrorMessage(error, "로그아웃하지 못했습니다."));
    }
  };

  const revokeAll = async () => {
    setBusy(true);
    try {
      const count = await revokeAllSessions();
      setSession(null);
      setRevokeAllOpen(false);
      await queryClient.invalidateQueries();
      setMessage(`관리자 session ${count}개를 모두 폐기했습니다.`);
    } catch (error) {
      setMessage(apiErrorMessage(error, "전체 session을 폐기하지 못했습니다."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        authenticated: session !== null,
        actor: session?.actor ?? null,
        runAction: async (path) => setConfirmPath(path),
        openLogin: showLogin,
        logout,
        revokeAll: () => setRevokeAllOpen(true),
      }}
    >
      {children}
      {confirmPath ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" role="presentation">
          <section className="w-full max-w-md border border-zinc-700 bg-zinc-950 p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
            <h2 id="confirm-title" className="text-lg font-semibold">운영 명령 확인</h2>
            <p className="mt-3 text-sm leading-6 text-zinc-500">
              {actionDescription(confirmPath)} 실행 결과는 감사 timeline에 기록되며 idempotency key로 중복 적용을 차단합니다.
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setConfirmPath(null)}>취소</Button>
              <Button variant={confirmPath.includes("emergency") ? "danger" : "default"} onClick={() => {
                const path = confirmPath;
                setConfirmPath(null);
                void execute(path);
              }}>확인 후 실행</Button>
            </div>
          </section>
        </div>
      ) : null}
      {revokeAllOpen ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" role="presentation">
          <section className="w-full max-w-md border border-red-900 bg-zinc-950 p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="revoke-all-title">
            <h2 id="revoke-all-title" className="text-lg font-semibold">모든 관리자 session 폐기</h2>
            <p className="mt-3 text-sm leading-6 text-zinc-500">현재 관리자 ID로 로그인한 모든 브라우저를 즉시 로그아웃합니다. VPSGuard edge 트래픽 처리는 중단하지 않습니다.</p>
            <div className="mt-6 flex justify-end gap-2"><Button variant="ghost" onClick={() => setRevokeAllOpen(false)}>취소</Button><Button variant="danger" disabled={busy} onClick={() => void revokeAll()}>{busy ? "폐기 중" : "모두 로그아웃"}</Button></div>
          </section>
        </div>
      ) : null}
      {open ? (
        <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-black/70 p-4" role="presentation">
          <section className="my-6 w-full max-w-lg border border-zinc-700 bg-zinc-950 p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="auth-title">
            <div className="flex items-start justify-between gap-4">
              <div>
                <KeyRound className="mb-4 size-5 text-orange-400" aria-hidden="true" />
                <h2 id="auth-title" className="text-lg font-semibold">{authTitle(view)}</h2>
                <p className="mt-2 text-sm leading-6 text-zinc-500">{authDescription(view)}</p>
              </div>
              {view !== "recovery-codes" ? (
                <Button variant="ghost" size="icon" onClick={() => setOpen(false)} aria-label="닫기"><X className="size-4" /></Button>
              ) : null}
            </div>
            <div aria-live="polite" className="mt-3 min-h-5 whitespace-pre-line text-sm text-red-400">{message}</div>
            {view === "login" ? (
              <LoginForm username={username} password={password} secondFactor={secondFactor} useRecovery={useRecovery} busy={busy} onUsername={setUsername} onPassword={setPassword} onSecondFactor={setSecondFactor} onUseRecovery={setUseRecovery} onSubmit={submitLogin} onBreakGlass={() => setView("break-glass")} />
            ) : null}
            {view === "setup-account" ? (
              <SetupAccountForm username={username} password={password} passwordConfirm={passwordConfirm} bootstrapCode={bootstrapCode} busy={busy} onUsername={setUsername} onPassword={setPassword} onPasswordConfirm={setPasswordConfirm} onBootstrapCode={setBootstrapCode} onSubmit={submitSetupAccount} />
            ) : null}
            {view === "setup-totp" && enrollment ? (
              <TotpSetupForm enrollment={enrollment} code={secondFactor} busy={busy} onCode={setSecondFactor} onSubmit={submitSetupTotp} />
            ) : null}
            {view === "recovery-codes" ? (
              <RecoveryCodes codes={recoveryCodes} onFinish={() => {
                setRecoveryCodes([]);
                setEnrollment(null);
                setOpen(false);
                setMessage("관리자 계정과 2단계 인증을 등록했습니다.");
              }} />
            ) : null}
            {view === "break-glass" ? (
              <BreakGlassForm code={bootstrapCode} busy={busy} onCode={setBootstrapCode} onSubmit={submitBreakGlass} onBack={() => setView("login")} />
            ) : null}
          </section>
        </div>
      ) : null}
      {message && !open ? (
        <button type="button" className="fixed bottom-5 right-5 z-50 whitespace-pre-line border border-zinc-700 bg-zinc-100 px-4 py-3 text-left text-xs font-semibold text-zinc-950 shadow-xl" onClick={() => setMessage(null)}>{message}</button>
      ) : null}
    </AuthContext.Provider>
  );
}

interface FormStateProps {
  busy: boolean;
  onSubmit: (event: FormEvent) => void;
}

function LoginForm(props: FormStateProps & {
  username: string; password: string; secondFactor: string; useRecovery: boolean;
  onUsername: (value: string) => void; onPassword: (value: string) => void;
  onSecondFactor: (value: string) => void; onUseRecovery: (value: boolean) => void;
  onBreakGlass: () => void;
}) {
  return (
    <form className="mt-4 space-y-4" onSubmit={props.onSubmit}>
      <Field id="admin-username" label="관리자 ID" value={props.username} onValue={props.onUsername} autoComplete="username" />
      <Field id="admin-password" label="비밀번호" type="password" value={props.password} onValue={props.onPassword} autoComplete="current-password" />
      <Field id="admin-second-factor" label={props.useRecovery ? "복구 코드" : "인증기 6자리 코드"} value={props.secondFactor} onValue={props.onSecondFactor} autoComplete="one-time-code" inputMode={props.useRecovery ? "text" : "numeric"} />
      <label className="flex items-center gap-2 text-xs text-zinc-400"><input type="checkbox" checked={props.useRecovery} onChange={(event) => props.onUseRecovery(event.target.checked)} /> 인증기 대신 일회용 복구 코드 사용</label>
      <Button className="w-full" disabled={props.busy} type="submit">{props.busy ? "확인 중" : "로그인"}</Button>
      <button type="button" className="text-xs text-zinc-500 underline underline-offset-4" onClick={props.onBreakGlass}>서버 단회 코드로 긴급 복구</button>
    </form>
  );
}

function SetupAccountForm(props: FormStateProps & {
  username: string; password: string; passwordConfirm: string; bootstrapCode: string;
  onUsername: (value: string) => void; onPassword: (value: string) => void;
  onPasswordConfirm: (value: string) => void; onBootstrapCode: (value: string) => void;
}) {
  return (
    <form className="mt-4 space-y-4" onSubmit={props.onSubmit}>
      <Field id="setup-code" label="최초 설정 단회 코드" type="password" value={props.bootstrapCode} onValue={props.onBootstrapCode} autoComplete="one-time-code" />
      <Field id="setup-username" label="VPSGuard 관리자 ID" value={props.username} onValue={props.onUsername} autoComplete="username" />
      <Field id="setup-password" label="비밀번호 (12자 이상)" type="password" value={props.password} onValue={props.onPassword} autoComplete="new-password" minLength={12} />
      <Field id="setup-password-confirm" label="비밀번호 확인" type="password" value={props.passwordConfirm} onValue={props.onPasswordConfirm} autoComplete="new-password" minLength={12} />
      <Button className="w-full" disabled={props.busy} type="submit">{props.busy ? "보호 중" : "2단계 인증 등록 계속"}</Button>
    </form>
  );
}

function TotpSetupForm({ enrollment, code, busy, onCode, onSubmit }: FormStateProps & { enrollment: EnrollmentStart; code: string; onCode: (value: string) => void }) {
  return (
    <form className="mt-4 space-y-4" onSubmit={onSubmit}>
      <div className="border border-zinc-800 bg-zinc-900 p-4">
        <div className="text-xs text-zinc-500">인증 앱에 아래 키를 직접 입력하십시오.</div>
        <code className="mt-2 block break-all font-mono text-sm text-orange-300">{enrollment.secret_base32}</code>
        <a className="mt-3 inline-block text-xs text-zinc-400 underline" href={enrollment.otpauth_uri}>이 기기의 인증 앱에서 열기</a>
      </div>
      <Field id="setup-totp" label="인증기 6자리 코드" value={code} onValue={onCode} autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" />
      <Button className="w-full" disabled={busy} type="submit">{busy ? "확인 중" : "등록 완료"}</Button>
    </form>
  );
}

function RecoveryCodes({ codes, onFinish }: { codes: string[]; onFinish: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <div className="mt-4">
      <div className="border border-amber-700/60 bg-amber-950/30 p-4 text-sm text-amber-200">이 코드는 지금 한 번만 표시됩니다. 비밀번호 관리자나 안전한 오프라인 장소에 보관하십시오.</div>
      <ol className="mt-4 grid grid-cols-1 gap-2 border-y border-zinc-800 py-4 sm:grid-cols-2">{codes.map((code) => <li key={code}><code className="font-mono text-xs">{code}</code></li>)}</ol>
      <Button variant="outline" className="mt-4 w-full" onClick={() => void navigator.clipboard.writeText(codes.join("\n"))}>복구 코드 복사</Button>
      <label className="mt-4 flex items-start gap-2 text-xs text-zinc-400"><input className="mt-0.5" type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} /> 복구 코드를 안전한 장소에 저장했습니다.</label>
      <Button className="mt-4 w-full" disabled={!saved} onClick={onFinish}><ShieldCheck className="size-4" /> 관리자 화면 시작</Button>
    </div>
  );
}

function BreakGlassForm({ code, busy, onCode, onSubmit, onBack }: FormStateProps & { code: string; onCode: (value: string) => void; onBack: () => void }) {
  return (
    <form className="mt-4 space-y-4" onSubmit={onSubmit}>
      <Field id="break-glass-code" label="서버 단회 복구 코드" type="password" value={code} onValue={onCode} autoComplete="one-time-code" />
      <div className="flex gap-2"><Button variant="ghost" type="button" onClick={onBack}>일반 로그인</Button><Button className="flex-1" disabled={busy} type="submit">{busy ? "확인 중" : "긴급 session 시작"}</Button></div>
    </form>
  );
}

function Field({ id, label, value, onValue, type = "text", ...inputProps }: {
  id: string; label: string; value: string; onValue: (value: string) => void; type?: string;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "value" | "onChange" | "type">) {
  return <div><label htmlFor={id} className="block font-mono text-[10px] uppercase tracking-wider text-zinc-500">{label}</label><input id={id} type={type} value={value} onChange={(event) => onValue(event.target.value)} className="mt-2 h-10 w-full border border-zinc-700 bg-zinc-900 px-3 text-sm outline-none focus:border-orange-500" required {...inputProps} /></div>;
}

function authTitle(view: AuthView): string {
  if (view === "setup-account") return "최초 관리자 등록";
  if (view === "setup-totp") return "2단계 인증 연결";
  if (view === "recovery-codes") return "복구 코드 보관";
  if (view === "break-glass") return "긴급 복구 로그인";
  return "VPSGuard 관리자 로그인";
}

function authDescription(view: AuthView): string {
  if (view === "setup-account") return "Linux·SSH 계정과 분리된 VPSGuard 전용 관리자를 만듭니다.";
  if (view === "setup-totp") return "인증 앱에 VPSGuard 계정을 추가한 뒤 현재 코드를 확인합니다.";
  if (view === "recovery-codes") return "인증기를 잃었을 때 비밀번호와 함께 사용할 일회용 코드입니다.";
  if (view === "break-glass") return "터미널은 최초 설정과 계정 복구 때만 사용합니다.";
  return "관리자 ID·비밀번호와 인증기 코드를 입력하십시오.";
}

function actionDescription(path: string): string {
  if (path.includes("emergency-proxy")) return "Cloudflare 비상 보호와 검증된 원본 잠금을";
  if (path.includes("provider-restore")) return "저장된 provider snapshot 복구를";
  if (path.includes("manual-hold")) return "자동 상태 전이의 수동 고정을";
  return "자동 상태 전이 재개를";
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider가 필요합니다.");
  return value;
}
