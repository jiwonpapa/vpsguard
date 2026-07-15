import type {
  ActionResponse,
  CertbotAssistedPlan,
  ClientRow,
  EventRow,
  ListResponse,
  ResourcesResponse,
  RouteRow,
  SeriesPoint,
  StatusResponse,
  TrafficSummary,
} from "./types";

let csrfToken = "";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(
      body.error?.problem ?? `요청 실패 (${response.status})`,
      response.status,
      body.error?.code,
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

export async function createSession(token: string): Promise<void> {
  const response = await fetch("/api/v1/session", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ login_code: token }),
  });
  const body = await parseResponse<{ csrf_token: string }>(response);
  csrfToken = body.csrf_token;
}

export async function restoreSession(): Promise<boolean> {
  const response = await fetch("/api/v1/session", {
    cache: "no-store",
    credentials: "same-origin",
  });
  if (response.status === 401) {
    csrfToken = "";
    return false;
  }
  const body = await parseResponse<{ csrf_token: string }>(response);
  csrfToken = body.csrf_token;
  return true;
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

export const api = {
  status: () => getJson<StatusResponse>("/api/v1/status"),
  summary: () => getJson<TrafficSummary>("/api/v1/traffic/summary"),
  series: () =>
    getJson<ListResponse<SeriesPoint>>("/api/v1/traffic/series").then(
      (value) => value.items,
    ),
  clients: () =>
    getJson<ListResponse<ClientRow>>("/api/v1/clients?limit=500").then(
      (value) => value.items,
    ),
  routes: () =>
    getJson<ListResponse<RouteRow>>("/api/v1/routes?limit=500").then(
      (value) => value.items,
    ),
  incidents: () =>
    getJson<ListResponse<EventRow>>("/api/v1/incidents?limit=200").then(
      (value) => value.items,
    ),
  resources: () => getJson<ResourcesResponse>("/api/v1/resources"),
  tlsAssistedPlan: requestTlsAssistedPlan,
};
