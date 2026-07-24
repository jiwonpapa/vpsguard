import type {
  ActionResponse,
  CertbotAssistedPlan,
  BotRow,
  ClientDetailRow,
  ClientRow,
  CorrelationResponse,
  EventRow,
  FirewallApplyResult,
  FirewallStatus,
  ListResponse,
  PendingFirewallPlan,
  ProtectionApplyResult,
  ProtectionPlan,
  ProtectionSettings,
  ProtectionSettingsStatus,
  ResourcesResponse,
  RouteRow,
  SeriesPoint,
  StatusResponse,
  TrafficSummary,
  UfwMutation,
} from "./types";

let csrfToken = "";

export interface AuthStatus {
  auth_provider: "local" | "pam";
  setup_required: boolean;
  enrollment_enabled: boolean;
  password_login_enabled: boolean;
  totp_required: boolean;
  break_glass_available: boolean;
}

async function authenticatedJson<T>(
  path: string,
  body: unknown,
  idempotencyKey?: string,
): Promise<T> {
  if (!csrfToken) {
    throw new ApiError("운영 session 로그인이 필요합니다.", 401, "SESSION_REQUIRED");
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken,
  };
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers,
    body: JSON.stringify(body),
  });
  try {
    return await parseResponse<T>(response);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.code === "CSRF_AUTH_REQUIRED")) {
      csrfToken = "";
    }
    throw error;
  }
}

export interface SessionInfo {
  csrf_token: string;
  expires_in_seconds: number;
  actor: string;
  authentication_method: string;
}

export interface EnrollmentStart {
  enrollment_id: string;
  secret_base32: string;
  otpauth_uri: string;
  expires_in_seconds: number;
}

export interface EnrollmentComplete {
  recovery_codes: string[];
  session: SessionInfo;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly causeDetail?: string,
    public readonly impact?: string,
    public readonly nextAction?: string,
    public readonly eventId?: string,
    public readonly requestId?: string | null,
  ) {
    super(message);
  }
}

export function apiErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) {
    return error instanceof Error ? error.message : fallback;
  }
  return [
    error.message,
    error.causeDetail ? `원인: ${error.causeDetail}` : null,
    error.impact ? `영향: ${error.impact}` : null,
    error.nextAction ? `다음 조치: ${error.nextAction}` : null,
    error.eventId ? `오류 ID: ${error.eventId}` : null,
    error.requestId ? `요청 ID: ${error.requestId}` : null,
  ]
    .filter((value): value is string => value !== null)
    .join("\n");
}

async function parseResponse<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(
      body.error?.problem ?? `요청 실패 (${response.status})`,
      response.status,
      body.error?.code,
      body.error?.cause,
      body.error?.impact,
      body.error?.next_action,
      body.error?.event_id,
      response.headers.get("x-request-id"),
    );
  }
  return body as T;
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
  });
  return parseResponse<T>(response);
}

export function correlationPath(correlationId: string): string {
  const bounded = correlationId.trim();
  if (!bounded) throw new Error("상관관계 ID를 입력하십시오.");
  return `/api/v1/correlations/${encodeURIComponent(bounded)}`;
}

async function sessionRequest(body: Record<string, string>): Promise<SessionInfo> {
  const response = await fetch("/api/v1/session", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const session = await parseResponse<SessionInfo>(response);
  csrfToken = session.csrf_token;
  return session;
}

export function getAuthStatus(): Promise<AuthStatus> {
  return getJson<AuthStatus>("/api/v1/auth/status");
}

export function loginWithTotp(
  username: string,
  password: string,
  totpCode: string,
): Promise<SessionInfo> {
  return sessionRequest({ username, password, totp_code: totpCode });
}

export function loginWithRecoveryCode(
  username: string,
  password: string,
  recoveryCode: string,
): Promise<SessionInfo> {
  return sessionRequest({ username, password, recovery_code: recoveryCode });
}

export function createBreakGlassSession(token: string): Promise<SessionInfo> {
  return sessionRequest({ login_code: token });
}

export async function startEnrollment(
  loginCode: string,
  username: string,
  password: string,
): Promise<EnrollmentStart> {
  const response = await fetch("/api/v1/auth/enrollment", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_code: loginCode, username, password }),
  });
  return parseResponse<EnrollmentStart>(response);
}

export async function confirmEnrollment(
  enrollmentId: string,
  totpCode: string,
): Promise<EnrollmentComplete> {
  const response = await fetch("/api/v1/auth/enrollment/confirm", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enrollment_id: enrollmentId, totp_code: totpCode }),
  });
  const complete = await parseResponse<EnrollmentComplete>(response);
  csrfToken = complete.session.csrf_token;
  return complete;
}

export async function restoreSession(): Promise<SessionInfo | null> {
  const response = await fetch("/api/v1/session", {
    cache: "no-store",
    credentials: "same-origin",
  });
  if (response.status === 401) {
    csrfToken = "";
    return null;
  }
  const body = await parseResponse<SessionInfo>(response);
  csrfToken = body.csrf_token;
  return body;
}

export async function logoutSession(): Promise<void> {
  if (!csrfToken) return;
  const response = await fetch("/api/v1/session", {
    method: "DELETE",
    credentials: "same-origin",
    headers: { "X-CSRF-Token": csrfToken },
  });
  await parseResponse(response);
  csrfToken = "";
}

export async function revokeAllSessions(): Promise<number> {
  if (!csrfToken) {
    throw new ApiError("관리자 로그인이 필요합니다.", 401, "SESSION_REQUIRED");
  }
  const response = await fetch("/api/v1/sessions/revoke-all", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-CSRF-Token": csrfToken },
  });
  const body = await parseResponse<{ revoked_sessions: number }>(response);
  csrfToken = "";
  return body.revoked_sessions;
}

export async function performAction(path: string): Promise<ActionResponse> {
  if (!csrfToken) {
    throw new ApiError("운영 session 로그인이 필요합니다.", 401, "SESSION_REQUIRED");
  }
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-CSRF-Token": csrfToken,
      "Idempotency-Key": crypto.randomUUID(),
    },
  });
  try {
    return await parseResponse<ActionResponse>(response);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.code === "CSRF_AUTH_REQUIRED")) {
      csrfToken = "";
    }
    throw error;
  }
}

export async function requestTlsAssistedPlan(email: string): Promise<CertbotAssistedPlan> {
  if (!csrfToken) {
    throw new ApiError("운영 session 로그인이 필요합니다.", 401, "SESSION_REQUIRED");
  }
  const response = await fetch("/api/v1/tls/assisted-plan", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken,
    },
    body: JSON.stringify({ email }),
  });
  return parseResponse<CertbotAssistedPlan>(response);
}

export function requestFirewallPlan(mutation: UfwMutation): Promise<PendingFirewallPlan> {
  return authenticatedJson<PendingFirewallPlan>("/api/v1/firewall/plan", mutation);
}

export function applyFirewallPlan(operationId: string): Promise<FirewallApplyResult> {
  return authenticatedJson<FirewallApplyResult>("/api/v1/firewall/apply", {
    operation_id: operationId,
  });
}

export function requestProtectionPlan(settings: ProtectionSettings): Promise<ProtectionPlan> {
  return authenticatedJson<ProtectionPlan>("/api/v1/settings/protection/plan", { settings });
}

export function applyProtectionPlan(plan: ProtectionPlan): Promise<ProtectionApplyResult> {
  return authenticatedJson<ProtectionApplyResult>(
    "/api/v1/settings/protection/apply",
    {
      settings: plan.settings,
      current_fingerprint: plan.current_fingerprint,
      plan_hash: plan.plan_hash,
    },
    crypto.randomUUID(),
  );
}

export const api = {
  status: () => getJson<StatusResponse>("/api/v1/status"),
  summary: () => getJson<TrafficSummary>("/api/v1/traffic/summary"),
  series: (resolution: "1s" | "10s" | "1m" = "1m") =>
    getJson<ListResponse<SeriesPoint>>(`/api/v1/traffic/series?resolution=${resolution}`).then(
      (value) => value.items,
    ),
  clients: () =>
    getJson<ListResponse<ClientRow>>("/api/v1/clients?limit=500").then(
      (value) => value.items,
    ),
  clientDetail: (clientIp: string) =>
    getJson<ClientDetailRow>(`/api/v1/clients/${encodeURIComponent(clientIp)}`),
  routes: () =>
    getJson<ListResponse<RouteRow>>("/api/v1/routes?limit=500").then(
      (value) => value.items,
    ),
  bots: () =>
    getJson<ListResponse<BotRow>>("/api/v1/bots?limit=100").then(
      (value) => value.items,
    ),
  incidents: () =>
    getJson<ListResponse<EventRow>>("/api/v1/incidents?limit=200").then(
      (value) => value.items,
    ),
  correlation: (correlationId: string) =>
    getJson<CorrelationResponse>(correlationPath(correlationId)),
  resources: () => getJson<ResourcesResponse>("/api/v1/resources"),
  firewall: () => getJson<FirewallStatus>("/api/v1/firewall"),
  firewallPlan: requestFirewallPlan,
  firewallApply: applyFirewallPlan,
  protection: () =>
    getJson<ProtectionSettingsStatus>("/api/v1/settings/protection"),
  protectionPlan: requestProtectionPlan,
  protectionApply: applyProtectionPlan,
  tlsAssistedPlan: requestTlsAssistedPlan,
};
