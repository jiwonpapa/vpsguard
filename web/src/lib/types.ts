export interface StatusResponse {
  schema_version: number;
  mode: string;
  manual_hold: boolean;
  policy_version: number;
  last_transition_at: string;
  reasons: string[];
  edge: string;
  origin: string;
  agent: string;
  provider: string;
  tls: string;
  tls_management: TlsManagementSnapshot;
}

export interface TlsManagementSnapshot {
  health: string;
  ownership: string;
  renewal: string;
  manager: string | null;
  certificate_count: number;
  earliest_expiry: string | null;
  error_code: string | null;
  next_action: string;
}

export interface CertbotAssistedPlan {
  schema_version: number;
  domains: string[];
  email: string;
  webroot: string;
  steps: string[];
  requires_explicit_approval: boolean;
  preserves_existing_manager: boolean;
}

export interface TrafficSummary {
  requests: number;
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_5xx: number;
  throttled: number;
  denied: number;
  challenged: number;
  latency_p95_micros: number;
  unique_clients: number;
  dropped_clients: number;
  request_body_bytes: number;
  response_body_bytes: number;
  upstream_connections: number;
  upstream_connections_reused: number;
}

export interface OsSnapshot {
  load_1m: number;
  memory_total_bytes: number;
  memory_available_bytes: number;
  swap_total_bytes: number;
  swap_free_bytes: number;
  uptime_seconds: number;
}

export interface CollectorHealth {
  name: string;
  state: string;
  last_success_at: string | null;
  error_code: string | null;
}

export interface ResourcesResponse {
  state: string;
  os: OsSnapshot | null;
  services: CollectorHealth[];
}

export interface ClientRow {
  client_ip: string;
  requests: number;
  throttled: number;
  denied: number;
  request_body_bytes: number;
  response_body_bytes: number;
  last_seen_unix_ms: number;
}

export interface RouteRow {
  normalized_route: string;
  route_class: string;
  requests: number;
  errors: number;
  latency_avg_micros: number;
  max_route_cost: number;
  request_body_bytes: number;
  response_body_bytes: number;
}

export interface SeriesPoint {
  bucket_unix_ms: number;
  requests: number;
  errors: number;
  throttled: number;
  latency_avg_micros: number;
  request_body_bytes: number;
  response_body_bytes: number;
}

export interface GuardEventPayload {
  schema_version: number;
  event_id: string;
  occurred_at: string;
  severity: string;
  kind: string;
  summary: string;
  reason_codes: string[];
  evidence: Record<string, string>;
  action: Record<string, string>;
  result: Record<string, string>;
  recovery: Record<string, string>;
}

export interface EventRow {
  event_id: string;
  occurred_at: string;
  severity: string;
  kind: string;
  payload: GuardEventPayload;
}

export interface ListResponse<T> {
  items: T[];
}

export interface ActionResponse {
  applied: boolean;
  mode: string;
  operation_id: string;
}
