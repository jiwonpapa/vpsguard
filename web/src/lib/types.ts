export interface StatusResponse {
  schema_version: number;
  inspection: "profiled" | "protocol_only";
  security: {
    app_layer_active: boolean;
    baseline_response_headers: boolean;
    strip_origin_headers: boolean;
    csp_mode: "off" | "report_only" | "enforce";
    hsts_max_age_seconds: number;
    auth_rate_limit_rpm: number | null;
  };
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
  unit: string | null;
  collected_at_unix_ms: number | null;
  resource_state: string | null;
  semantic_state: string | null;
  resource_error_code: string | null;
  semantic_error_code: string | null;
  resources: CgroupSnapshot | null;
  semantic: ServiceSemanticSnapshot | null;
}

export interface CgroupSnapshot {
  collected_at_unix_ms: number;
  cpu_usage_usec: number;
  cpu_user_usec: number;
  cpu_system_usec: number;
  cpu_nr_throttled: number;
  cpu_throttled_usec: number;
  cpu_usage_milli_percent: number | null;
  memory_current_bytes: number;
  memory_peak_bytes: number | null;
  memory_high_events: number;
  memory_max_events: number;
  oom_events: number;
  oom_kill_events: number;
  io_read_bytes: number;
  io_write_bytes: number;
  process_count: number;
  task_count: number;
}

export type ServiceSemanticSnapshot =
  | { kind: "tcp_health" }
  | { kind: "nginx"; active_connections: number; accepts: number; handled: number; requests: number; reading: number; writing: number; waiting: number }
  | { kind: "apache"; total_accesses: number; total_kbytes: number; busy_workers: number; idle_workers: number }
  | { kind: "php_fpm"; accepted_connections: number; listen_queue: number; max_listen_queue: number; listen_queue_length: number; idle_processes: number; active_processes: number; total_processes: number; max_active_processes: number; max_children_reached: number; slow_requests: number }
  | { kind: "mysql"; max_connections: number; threads_connected: number; threads_running: number; slow_queries: number; innodb_row_lock_current_waits: number; total_connections: number; aborted_connects: number }
  | { kind: "redis"; used_memory_bytes: number; connected_clients: number; blocked_clients: number; keyspace_hits: number; keyspace_misses: number; evicted_keys: number };

export interface StorageHealth {
  condition: "healthy" | "degraded" | "critical";
  queue_depth: number;
  queue_capacity: number;
  queue_dropped_samples: number;
  write_dropped_samples: number;
  persisted_samples: number;
  persisted_batches: number;
  write_failures: number;
  database_bytes: number;
  database_used_bytes: number;
  reclaimable_bytes: number;
  wal_bytes: number;
  disk_available_bytes: number | null;
  max_database_bytes: number;
  min_disk_free_bytes: number;
  database_budget_exceeded: boolean;
  disk_space_low: boolean;
  last_batch_at_unix_ms: number | null;
  last_rollup_at_unix_ms: number | null;
  last_retention_at_unix_ms: number | null;
  last_write_error_at_unix_ms: number | null;
  retention_deleted_rows: number;
}

export interface ResourcesResponse {
  state: string;
  os: OsSnapshot | null;
  services: CollectorHealth[];
  storage: StorageHealth;
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

export interface RequestTraceRow {
  request_id: string;
  occurred_at_unix_ms: number;
  method: string;
  route_class: string;
  normalized_route: string;
  route_cost: number;
  status: number;
  latency_micros: number;
  request_body_bytes: number;
  response_body_bytes: number;
  upstream_connection_reused: boolean | null;
  decision: string;
  policy_version: number;
}

export interface AuditActionRow {
  operation_id: string;
  occurred_at: string;
  action: string;
  mode: string;
  result: string;
}

export interface CorrelationResponse {
  correlation_id: string;
  request: RequestTraceRow | null;
  events: EventRow[];
  audit_action: AuditActionRow | null;
}

export interface ListResponse<T> {
  items: T[];
}

export interface ActionResponse {
  applied: boolean;
  mode: string;
  operation_id: string;
}
