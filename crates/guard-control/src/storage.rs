//! SQLite WAL 기반 bounded traffic, rollup, 사건과 감사 저장소입니다.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use guard_core::GuardEvent;
use guard_core::config::RetentionConfig;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use thiserror::Error;

use crate::telemetry::{SeriesPoint, TelemetryEnvelope};

/// Control process의 bounded traffic persistence queue 크기입니다.
pub(crate) const TRAFFIC_QUEUE_CAPACITY: usize = 4_096;

const TEN_SECONDS_MS: u64 = 10_000;
const MINUTE_MS: u64 = 60_000;
const RETENTION_DELETE_LIMIT: u64 = 10_000;
const UNKNOWN_DISK_BYTES: u64 = u64::MAX;

/// SQLite 초기화·query·저장 실패입니다.
#[derive(Debug, Error)]
pub enum StorageError {
    /// database parent directory 생성 실패입니다.
    #[error("database directory 생성 실패: {0}")]
    Directory(#[from] std::io::Error),
    /// SQLite 작업 실패입니다.
    #[error("SQLite 작업 실패: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 사건 JSON 변환 실패입니다.
    #[error("사건 JSON 변환 실패: {0}")]
    Json(#[from] serde_json::Error),
}

/// client별 bounded aggregate row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ClientRow {
    pub(crate) client_ip: String,
    pub(crate) requests: u64,
    pub(crate) throttled: u64,
    pub(crate) denied: u64,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
    pub(crate) last_seen_unix_ms: u64,
}

/// 상세 보존 구간의 client별 판정·비용·route drill-down입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ClientDetailRow {
    pub(crate) client_ip: String,
    pub(crate) requests: u64,
    pub(crate) errors: u64,
    pub(crate) throttled: u64,
    pub(crate) challenged: u64,
    pub(crate) denied: u64,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
    pub(crate) max_route_cost: u8,
    pub(crate) last_decision: String,
    pub(crate) last_seen_unix_ms: u64,
    pub(crate) routes: Vec<ClientRouteRow>,
}

/// client 상세에서 반환하는 bounded route aggregate입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ClientRouteRow {
    pub(crate) normalized_route: String,
    pub(crate) route_class: String,
    pub(crate) requests: u64,
    pub(crate) errors: u64,
    pub(crate) throttled: u64,
    pub(crate) challenged: u64,
    pub(crate) denied: u64,
    pub(crate) max_route_cost: u8,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
}

/// route별 bounded aggregate row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RouteRow {
    pub(crate) normalized_route: String,
    pub(crate) route_class: String,
    pub(crate) requests: u64,
    pub(crate) errors: u64,
    pub(crate) latency_avg_micros: u64,
    pub(crate) max_route_cost: u8,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
}

/// 선언형 bot 분류별 bounded 장기 aggregate row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BotRow {
    pub(crate) bot_class: String,
    pub(crate) bot_provider: Option<String>,
    pub(crate) bot_verified: bool,
    pub(crate) bot_reason: String,
    pub(crate) user_agent_family: String,
    pub(crate) requests: u64,
    pub(crate) denied: u64,
    pub(crate) throttled: u64,
    pub(crate) response_body_bytes: u64,
}

/// 사건 API row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EventRow {
    pub(crate) event_id: String,
    pub(crate) occurred_at: String,
    pub(crate) severity: String,
    pub(crate) kind: String,
    pub(crate) payload: serde_json::Value,
}

/// 영속 notification 전송 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotificationDeliveryRecord {
    pub(crate) attempts: u8,
    pub(crate) delivered: bool,
    pub(crate) exhausted: bool,
}

/// 관리자 UI에 제공할 notification 영속 전송 요약입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NotificationDeliverySummary {
    pub(crate) delivered: u64,
    pub(crate) failed: u64,
    pub(crate) pending: u64,
    pub(crate) last_success_at: Option<String>,
    pub(crate) last_failure_at: Option<String>,
    pub(crate) last_error_code: Option<String>,
}

/// detail retention 안에서 request ID로 찾은 비식별 요청 추적 row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RequestTraceRow {
    pub(crate) request_id: String,
    pub(crate) occurred_at_unix_ms: u64,
    pub(crate) method: String,
    pub(crate) route_class: String,
    pub(crate) normalized_route: String,
    pub(crate) route_cost: u8,
    pub(crate) status: u16,
    pub(crate) latency_micros: u64,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
    pub(crate) upstream_connection_reused: Option<bool>,
    pub(crate) decision: String,
    pub(crate) policy_version: u64,
    pub(crate) bot_class: String,
    pub(crate) bot_provider: Option<String>,
    pub(crate) bot_verified: bool,
    pub(crate) bot_reason: String,
    pub(crate) user_agent_family: String,
}

/// operation ID로 찾은 감사 action row입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AuditActionRow {
    pub(crate) operation_id: String,
    pub(crate) occurred_at: String,
    pub(crate) action: String,
    pub(crate) mode: String,
    pub(crate) result: String,
}

/// 저장 계층의 현재 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageCondition {
    /// 현재 data loss나 공간 제한이 관측되지 않았습니다.
    Healthy,
    /// queue 또는 writer에서 sample 손실이 관측됐습니다.
    Degraded,
    /// database 예산 또는 최소 disk 여유를 위반했습니다.
    Critical,
}

/// API와 UI에 제공하는 non-blocking 저장소 health snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct StorageHealthSnapshot {
    pub(crate) condition: StorageCondition,
    pub(crate) queue_depth: u64,
    pub(crate) queue_capacity: u64,
    pub(crate) queue_dropped_samples: u64,
    pub(crate) write_dropped_samples: u64,
    pub(crate) persisted_samples: u64,
    pub(crate) persisted_batches: u64,
    pub(crate) write_failures: u64,
    pub(crate) database_bytes: u64,
    pub(crate) database_used_bytes: u64,
    pub(crate) reclaimable_bytes: u64,
    pub(crate) wal_bytes: u64,
    pub(crate) disk_available_bytes: Option<u64>,
    pub(crate) max_database_bytes: u64,
    pub(crate) min_disk_free_bytes: u64,
    pub(crate) database_budget_exceeded: bool,
    pub(crate) disk_space_low: bool,
    pub(crate) last_batch_at_unix_ms: Option<u64>,
    pub(crate) last_rollup_at_unix_ms: Option<u64>,
    pub(crate) last_retention_at_unix_ms: Option<u64>,
    pub(crate) last_write_error_at_unix_ms: Option<u64>,
    pub(crate) retention_deleted_rows: u64,
    pub(crate) retention_anonymized_rows: u64,
    pub(crate) retention_backlog: bool,
}

#[derive(Debug)]
struct StorageHealth {
    queue_depth: AtomicU64,
    queue_dropped_samples: AtomicU64,
    write_dropped_samples: AtomicU64,
    persisted_samples: AtomicU64,
    persisted_batches: AtomicU64,
    write_failures: AtomicU64,
    database_bytes: AtomicU64,
    database_used_bytes: AtomicU64,
    reclaimable_bytes: AtomicU64,
    wal_bytes: AtomicU64,
    disk_available_bytes: AtomicU64,
    database_budget_exceeded: AtomicBool,
    disk_space_low: AtomicBool,
    last_batch_at_unix_ms: AtomicU64,
    last_rollup_at_unix_ms: AtomicU64,
    last_retention_at_unix_ms: AtomicU64,
    last_write_error_at_unix_ms: AtomicU64,
    retention_deleted_rows: AtomicU64,
    retention_anonymized_rows: AtomicU64,
    retention_backlog: AtomicBool,
    max_database_bytes: u64,
    min_disk_free_bytes: u64,
}

impl StorageHealth {
    fn new(max_database_bytes: u64, min_disk_free_bytes: u64) -> Self {
        Self {
            queue_depth: AtomicU64::new(0),
            queue_dropped_samples: AtomicU64::new(0),
            write_dropped_samples: AtomicU64::new(0),
            persisted_samples: AtomicU64::new(0),
            persisted_batches: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            database_bytes: AtomicU64::new(0),
            database_used_bytes: AtomicU64::new(0),
            reclaimable_bytes: AtomicU64::new(0),
            wal_bytes: AtomicU64::new(0),
            disk_available_bytes: AtomicU64::new(UNKNOWN_DISK_BYTES),
            database_budget_exceeded: AtomicBool::new(false),
            disk_space_low: AtomicBool::new(false),
            last_batch_at_unix_ms: AtomicU64::new(0),
            last_rollup_at_unix_ms: AtomicU64::new(0),
            last_retention_at_unix_ms: AtomicU64::new(0),
            last_write_error_at_unix_ms: AtomicU64::new(0),
            retention_deleted_rows: AtomicU64::new(0),
            retention_anonymized_rows: AtomicU64::new(0),
            retention_backlog: AtomicBool::new(false),
            max_database_bytes,
            min_disk_free_bytes,
        }
    }

    fn snapshot(&self) -> StorageHealthSnapshot {
        let database_budget_exceeded = self.database_budget_exceeded.load(Ordering::Relaxed);
        let disk_space_low = self.disk_space_low.load(Ordering::Relaxed);
        let queue_dropped_samples = self.queue_dropped_samples.load(Ordering::Relaxed);
        let write_dropped_samples = self.write_dropped_samples.load(Ordering::Relaxed);
        let write_failures = self.write_failures.load(Ordering::Relaxed);
        let retention_backlog = self.retention_backlog.load(Ordering::Relaxed);
        let condition = if database_budget_exceeded || disk_space_low {
            StorageCondition::Critical
        } else if queue_dropped_samples > 0
            || write_dropped_samples > 0
            || write_failures > 0
            || retention_backlog
        {
            StorageCondition::Degraded
        } else {
            StorageCondition::Healthy
        };
        let disk_available_bytes = self.disk_available_bytes.load(Ordering::Relaxed);
        StorageHealthSnapshot {
            condition,
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            queue_capacity: TRAFFIC_QUEUE_CAPACITY as u64,
            queue_dropped_samples,
            write_dropped_samples,
            persisted_samples: self.persisted_samples.load(Ordering::Relaxed),
            persisted_batches: self.persisted_batches.load(Ordering::Relaxed),
            write_failures,
            database_bytes: self.database_bytes.load(Ordering::Relaxed),
            database_used_bytes: self.database_used_bytes.load(Ordering::Relaxed),
            reclaimable_bytes: self.reclaimable_bytes.load(Ordering::Relaxed),
            wal_bytes: self.wal_bytes.load(Ordering::Relaxed),
            disk_available_bytes: (disk_available_bytes != UNKNOWN_DISK_BYTES)
                .then_some(disk_available_bytes),
            max_database_bytes: self.max_database_bytes,
            min_disk_free_bytes: self.min_disk_free_bytes,
            database_budget_exceeded,
            disk_space_low,
            last_batch_at_unix_ms: nonzero(self.last_batch_at_unix_ms.load(Ordering::Relaxed)),
            last_rollup_at_unix_ms: nonzero(self.last_rollup_at_unix_ms.load(Ordering::Relaxed)),
            last_retention_at_unix_ms: nonzero(
                self.last_retention_at_unix_ms.load(Ordering::Relaxed),
            ),
            last_write_error_at_unix_ms: nonzero(
                self.last_write_error_at_unix_ms.load(Ordering::Relaxed),
            ),
            retention_deleted_rows: self.retention_deleted_rows.load(Ordering::Relaxed),
            retention_anonymized_rows: self.retention_anonymized_rows.load(Ordering::Relaxed),
            retention_backlog,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteRollupKey {
    bucket_unix_ms: u64,
    normalized_route: String,
    route_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientRollupKey {
    bucket_unix_ms: u64,
    client_ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BotRollupKey {
    bucket_unix_ms: u64,
    bot_class: String,
    bot_provider: String,
    bot_verified: bool,
    bot_reason: String,
    user_agent_family: String,
}

#[derive(Debug, Clone, Default)]
struct RouteRollupValue {
    requests: u64,
    errors: u64,
    throttled: u64,
    latency_sum_micros: u64,
    max_route_cost: u8,
    request_body_bytes: u64,
    response_body_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct ClientRollupValue {
    requests: u64,
    throttled: u64,
    denied: u64,
    request_body_bytes: u64,
    response_body_bytes: u64,
    last_seen_unix_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct BotRollupValue {
    requests: u64,
    denied: u64,
    throttled: u64,
    response_body_bytes: u64,
}

#[derive(Debug, Default)]
struct BatchRollups {
    ten_seconds: HashMap<RouteRollupKey, RouteRollupValue>,
    one_minute: HashMap<RouteRollupKey, RouteRollupValue>,
    clients: HashMap<ClientRollupKey, ClientRollupValue>,
    bots: HashMap<BotRollupKey, BotRollupValue>,
}

impl BatchRollups {
    fn from_telemetry(batch: &[TelemetryEnvelope], store_client_ip: bool) -> Self {
        let mut rollups = Self::default();
        for telemetry in batch {
            add_route_rollup(&mut rollups.ten_seconds, telemetry, TEN_SECONDS_MS);
            add_route_rollup(&mut rollups.one_minute, telemetry, MINUTE_MS);
            if store_client_ip && let Some(client_ip) = telemetry.client_ip {
                let key = ClientRollupKey {
                    bucket_unix_ms: bucket(telemetry.occurred_at_unix_ms, MINUTE_MS),
                    client_ip: client_ip.to_string(),
                };
                let value = rollups.clients.entry(key).or_default();
                value.requests = value.requests.saturating_add(1);
                value.throttled = value
                    .throttled
                    .saturating_add(u64::from(telemetry.decision == "throttle"));
                value.denied = value
                    .denied
                    .saturating_add(u64::from(telemetry.decision == "deny"));
                value.request_body_bytes = value
                    .request_body_bytes
                    .saturating_add(telemetry.request_body_bytes);
                value.response_body_bytes = value
                    .response_body_bytes
                    .saturating_add(telemetry.response_body_bytes);
                value.last_seen_unix_ms =
                    value.last_seen_unix_ms.max(telemetry.occurred_at_unix_ms);
            }
            if telemetry.bot_class != guard_core::BotClass::Undeclared {
                let key = BotRollupKey {
                    bucket_unix_ms: bucket(telemetry.occurred_at_unix_ms, MINUTE_MS),
                    bot_class: telemetry.bot_class.as_str().to_owned(),
                    bot_provider: telemetry.bot_provider.map_or_else(
                        || "none".to_owned(),
                        |provider| provider.as_str().to_owned(),
                    ),
                    bot_verified: telemetry.bot_verified,
                    bot_reason: telemetry.bot_reason.as_str().to_owned(),
                    user_agent_family: telemetry.user_agent_family.as_str().to_owned(),
                };
                let value = rollups.bots.entry(key).or_default();
                value.requests = value.requests.saturating_add(1);
                value.denied = value
                    .denied
                    .saturating_add(u64::from(telemetry.decision == "deny"));
                value.throttled = value
                    .throttled
                    .saturating_add(u64::from(telemetry.decision == "throttle"));
                value.response_body_bytes = value
                    .response_body_bytes
                    .saturating_add(telemetry.response_body_bytes);
            }
        }
        rollups
    }
}

/// 계층별 retention cutoff입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetentionCutoffs {
    detail_since_ms: u64,
    raw_ip_since_ms: u64,
    aggregate_since_ms: u64,
    incident_since_seconds: u64,
    audit_since_seconds: u64,
}

impl RetentionCutoffs {
    /// 현재 시각과 설정에서 각 독립 계층의 cutoff를 계산합니다.
    pub(crate) fn from_config(retention: &RetentionConfig, now_ms: u64) -> Self {
        Self {
            detail_since_ms: now_ms.saturating_sub(hours_to_millis(retention.detail_hours)),
            raw_ip_since_ms: now_ms.saturating_sub(days_to_millis(retention.raw_ip_days)),
            aggregate_since_ms: now_ms.saturating_sub(days_to_millis(retention.aggregate_days)),
            incident_since_seconds: now_ms.saturating_sub(days_to_millis(retention.incident_days))
                / 1_000,
            audit_since_seconds: now_ms.saturating_sub(days_to_millis(retention.audit_days))
                / 1_000,
        }
    }

    #[cfg(test)]
    fn new(
        detail_since_ms: u64,
        raw_ip_since_ms: u64,
        aggregate_since_ms: u64,
        incident_since_seconds: u64,
        audit_since_seconds: u64,
    ) -> Self {
        Self {
            detail_since_ms,
            raw_ip_since_ms,
            aggregate_since_ms,
            incident_since_seconds,
            audit_since_seconds,
        }
    }
}

/// connection 한 개를 mutex로 보호하는 소형 VPS용 SQLite 저장소입니다.
#[derive(Debug)]
pub(crate) struct SqliteStore {
    connection: Mutex<Connection>,
    database_path: Option<PathBuf>,
    store_client_ip: bool,
    health: StorageHealth,
}

impl SqliteStore {
    /// WAL database를 열고 migration을 적용합니다.
    pub(crate) fn open(
        path: &Path,
        max_database_bytes: u64,
        min_disk_free_bytes: u64,
        store_client_ip: bool,
    ) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        let store = Self::from_connection(
            connection,
            Some(path.to_path_buf()),
            max_database_bytes,
            min_disk_free_bytes,
            store_client_ip,
        )?;
        store.refresh_health()?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?, None, u64::MAX, 0, true)
    }

    fn from_connection(
        mut connection: Connection,
        database_path: Option<PathBuf>,
        max_database_bytes: u64,
        min_disk_free_bytes: u64,
        store_client_ip: bool,
    ) -> Result<Self, StorageError> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                occurred_at_ms INTEGER NOT NULL,
                method TEXT NOT NULL DEFAULT '',
                client_ip TEXT,
                route_class TEXT NOT NULL,
                normalized_route TEXT NOT NULL,
                route_cost INTEGER NOT NULL,
                status INTEGER NOT NULL,
                latency_micros INTEGER NOT NULL,
                request_body_bytes INTEGER NOT NULL DEFAULT 0,
                response_body_bytes INTEGER NOT NULL DEFAULT 0,
                upstream_connection_reused INTEGER,
                decision TEXT NOT NULL,
                policy_version INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS traffic_time_idx
                ON traffic_samples(occurred_at_ms);
            CREATE INDEX IF NOT EXISTS traffic_client_idx
                ON traffic_samples(client_ip, occurred_at_ms);
            CREATE INDEX IF NOT EXISTS traffic_route_idx
                ON traffic_samples(normalized_route, occurred_at_ms);
            CREATE TABLE IF NOT EXISTS guard_events (
                event_id TEXT PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_deliveries (
                event_id TEXT PRIMARY KEY REFERENCES guard_events(event_id) ON DELETE CASCADE,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt_at TEXT,
                delivered_at TEXT,
                last_error_code TEXT
            );
            CREATE INDEX IF NOT EXISTS notification_delivery_status_idx
                ON notification_deliveries(status, attempts);
            CREATE TABLE IF NOT EXISTS audit_actions (
                operation_id TEXT PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                action TEXT NOT NULL,
                mode TEXT NOT NULL,
                result TEXT NOT NULL
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);",
        )?;
        ensure_column(
            &connection,
            "request_body_bytes",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &connection,
            "response_body_bytes",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&connection, "upstream_connection_reused", "INTEGER")?;
        apply_rollup_migration(&mut connection)?;
        apply_correlation_migration(&mut connection)?;
        apply_bot_telemetry_migration(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_path,
            store_client_ip,
            health: StorageHealth::new(max_database_bytes, min_disk_free_bytes),
        })
    }

    /// queue 전송 전에 depth slot을 예약합니다.
    pub(crate) fn note_queue_send_started(&self) {
        self.health.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// queue full·closed로 전송하지 못한 sample을 기록합니다.
    pub(crate) fn note_queue_send_failed(&self) {
        atomic_saturating_decrement(&self.health.queue_depth);
        self.health
            .queue_dropped_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    /// writer가 queue에서 꺼낸 sample의 depth를 반영합니다.
    pub(crate) fn note_queue_dequeued(&self) {
        atomic_saturating_decrement(&self.health.queue_depth);
    }

    /// 공간 예산으로 저장하지 않은 sample 수를 기록합니다.
    pub(crate) fn note_write_rejected(&self, samples: usize) {
        self.health
            .write_dropped_samples
            .fetch_add(samples as u64, Ordering::Relaxed);
        self.health
            .last_write_error_at_unix_ms
            .store(system_time_millis(), Ordering::Relaxed);
    }

    /// 저장소가 새 traffic sample batch를 받을 수 있는지 반환합니다.
    pub(crate) fn accepts_traffic_writes(&self) -> bool {
        !self.health.database_budget_exceeded.load(Ordering::Relaxed)
            && !self.health.disk_space_low.load(Ordering::Relaxed)
    }

    /// telemetry batch를 단일 transaction으로 상세·10초·1분·client 계층에 저장합니다.
    pub(crate) fn record_traffic_batch(
        &self,
        batch: &[TelemetryEnvelope],
    ) -> Result<(), StorageError> {
        if batch.is_empty() {
            return Ok(());
        }
        let rollups = BatchRollups::from_telemetry(batch, self.store_client_ip);
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT INTO traffic_samples(
                    request_id, occurred_at_ms, method, client_ip, route_class,
                    normalized_route, route_cost, status, latency_micros,
                    request_body_bytes, response_body_bytes, upstream_connection_reused,
                    decision, policy_version, bot_class, bot_provider, bot_verified,
                    bot_reason, user_agent_family
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                           ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            )?;
            for telemetry in batch {
                let client_ip = self
                    .store_client_ip
                    .then(|| telemetry.client_ip.map(|value| value.to_string()))
                    .flatten();
                statement.execute(params![
                    telemetry.request_id,
                    to_i64(telemetry.occurred_at_unix_ms),
                    telemetry.method,
                    client_ip,
                    telemetry.route_class,
                    telemetry.normalized_route,
                    telemetry.route_cost,
                    telemetry.status,
                    to_i64(telemetry.latency_micros),
                    to_i64(telemetry.request_body_bytes),
                    to_i64(telemetry.response_body_bytes),
                    telemetry.upstream_connection_reused,
                    telemetry.decision,
                    to_i64(telemetry.policy_version),
                    telemetry.bot_class.as_str(),
                    telemetry.bot_provider.map(|provider| provider.as_str()),
                    telemetry.bot_verified,
                    telemetry.bot_reason.as_str(),
                    telemetry.user_agent_family.as_str(),
                ])?;
            }
        }
        upsert_route_rollups(&transaction, "traffic_rollups_10s", &rollups.ten_seconds)?;
        upsert_route_rollups(&transaction, "traffic_rollups_1m", &rollups.one_minute)?;
        upsert_client_rollups(&transaction, &rollups.clients)?;
        upsert_bot_rollups(&transaction, &rollups.bots)?;
        transaction.commit()?;
        drop(connection);

        let now = system_time_millis();
        self.health
            .persisted_samples
            .fetch_add(batch.len() as u64, Ordering::Relaxed);
        self.health
            .persisted_batches
            .fetch_add(1, Ordering::Relaxed);
        self.health
            .last_batch_at_unix_ms
            .store(now, Ordering::Relaxed);
        self.health
            .last_rollup_at_unix_ms
            .store(now, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_traffic(&self, telemetry: &TelemetryEnvelope) -> Result<(), StorageError> {
        self.record_traffic_batch(std::slice::from_ref(telemetry))
    }

    /// writer failure와 손실 sample 수를 기록합니다.
    pub(crate) fn note_write_failure(&self, samples: usize) {
        self.health.write_failures.fetch_add(1, Ordering::Relaxed);
        self.health
            .write_dropped_samples
            .fetch_add(samples as u64, Ordering::Relaxed);
        self.health
            .last_write_error_at_unix_ms
            .store(system_time_millis(), Ordering::Relaxed);
    }

    /// 최근 client aggregate를 반환합니다.
    pub(crate) fn clients(&self, limit: usize) -> Result<Vec<ClientRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT client_ip, SUM(requests), SUM(throttled), SUM(denied),
                    SUM(request_body_bytes), SUM(response_body_bytes), MAX(last_seen_ms)
             FROM traffic_client_rollups_1m
             GROUP BY client_ip ORDER BY SUM(requests) DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([to_i64(limit as u64)], |row| {
            Ok(ClientRow {
                client_ip: row.get(0)?,
                requests: from_i64(row.get(1)?),
                throttled: from_i64(row.get(2)?),
                denied: from_i64(row.get(3)?),
                request_body_bytes: from_i64(row.get(4)?),
                response_body_bytes: from_i64(row.get(5)?),
                last_seen_unix_ms: from_i64(row.get(6)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 상세 retention에 남은 exact client의 판정·비용과 bounded route 분해를 반환합니다.
    pub(crate) fn client_detail(
        &self,
        client_ip: &str,
        route_limit: usize,
    ) -> Result<Option<ClientDetailRow>, StorageError> {
        let connection = self.lock();
        let summary = connection.query_row(
            "SELECT COUNT(*),
                        SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                        SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN decision = 'challenge' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END),
                        SUM(request_body_bytes), SUM(response_body_bytes),
                        MAX(route_cost), MAX(occurred_at_ms)
                 FROM traffic_samples WHERE client_ip = ?1",
            [client_ip],
            |row| {
                let requests = from_i64(row.get(0)?);
                if requests == 0 {
                    return Ok(None);
                }
                Ok(Some((
                    requests,
                    from_i64(row.get(1)?),
                    from_i64(row.get(2)?),
                    from_i64(row.get(3)?),
                    from_i64(row.get(4)?),
                    from_i64(row.get(5)?),
                    from_i64(row.get(6)?),
                    from_i64(row.get(7)?).try_into().unwrap_or(u8::MAX),
                    from_i64(row.get(8)?),
                )))
            },
        )?;
        let Some((
            requests,
            errors,
            throttled,
            challenged,
            denied,
            request_body_bytes,
            response_body_bytes,
            max_route_cost,
            last_seen_unix_ms,
        )) = summary
        else {
            return Ok(None);
        };
        let last_decision = connection.query_row(
            "SELECT decision FROM traffic_samples
             WHERE client_ip = ?1 ORDER BY occurred_at_ms DESC, id DESC LIMIT 1",
            [client_ip],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT normalized_route, route_class, COUNT(*),
                    SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'challenge' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END),
                    MAX(route_cost), SUM(request_body_bytes), SUM(response_body_bytes)
             FROM traffic_samples WHERE client_ip = ?1
             GROUP BY normalized_route, route_class
             ORDER BY COUNT(*) DESC, normalized_route ASC LIMIT ?2",
        )?;
        let routes = statement
            .query_map(params![client_ip, to_i64(route_limit as u64)], |row| {
                Ok(ClientRouteRow {
                    normalized_route: row.get(0)?,
                    route_class: row.get(1)?,
                    requests: from_i64(row.get(2)?),
                    errors: from_i64(row.get(3)?),
                    throttled: from_i64(row.get(4)?),
                    challenged: from_i64(row.get(5)?),
                    denied: from_i64(row.get(6)?),
                    max_route_cost: from_i64(row.get(7)?).try_into().unwrap_or(u8::MAX),
                    request_body_bytes: from_i64(row.get(8)?),
                    response_body_bytes: from_i64(row.get(9)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(ClientDetailRow {
            client_ip: client_ip.to_owned(),
            requests,
            errors,
            throttled,
            challenged,
            denied,
            request_body_bytes,
            response_body_bytes,
            max_route_cost,
            last_decision,
            last_seen_unix_ms,
            routes,
        }))
    }

    /// Edge telemetry에서 마지막으로 관측한 policy version입니다.
    pub(crate) fn latest_policy_version(&self) -> Result<Option<u64>, StorageError> {
        let connection = self.lock();
        let value = connection.query_row(
            "SELECT MAX(policy_version) FROM traffic_samples",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(value.map(from_i64))
    }

    /// 장기 1분 rollup에서 route aggregate를 반환합니다.
    pub(crate) fn routes(&self, limit: usize) -> Result<Vec<RouteRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT normalized_route, route_class, SUM(requests), SUM(errors),
                    CAST(SUM(latency_sum_micros) / MAX(SUM(requests), 1) AS INTEGER),
                    MAX(max_route_cost), SUM(request_body_bytes), SUM(response_body_bytes)
             FROM traffic_rollups_1m GROUP BY normalized_route, route_class
             ORDER BY SUM(requests) DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([to_i64(limit as u64)], |row| {
            Ok(RouteRow {
                normalized_route: row.get(0)?,
                route_class: row.get(1)?,
                requests: from_i64(row.get(2)?),
                errors: from_i64(row.get(3)?),
                latency_avg_micros: from_i64(row.get(4)?),
                max_route_cost: row.get(5)?,
                request_body_bytes: from_i64(row.get(6)?),
                response_body_bytes: from_i64(row.get(7)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 장기 1분 rollup에서 선언형 bot aggregate를 반환합니다.
    pub(crate) fn bots(&self, limit: usize) -> Result<Vec<BotRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT bot_class, bot_provider, bot_verified, bot_reason, user_agent_family,
                    SUM(requests), SUM(denied), SUM(throttled), SUM(response_body_bytes)
             FROM traffic_bot_rollups_1m
             GROUP BY bot_class, bot_provider, bot_verified, bot_reason, user_agent_family
             ORDER BY SUM(requests) DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([to_i64(limit as u64)], |row| {
            let provider = row.get::<_, String>(1)?;
            Ok(BotRow {
                bot_class: row.get(0)?,
                bot_provider: (provider != "none").then_some(provider),
                bot_verified: row.get(2)?,
                bot_reason: row.get(3)?,
                user_agent_family: row.get(4)?,
                requests: from_i64(row.get(5)?),
                denied: from_i64(row.get(6)?),
                throttled: from_i64(row.get(7)?),
                response_body_bytes: from_i64(row.get(8)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 지정한 시각 이후 장기 1분 traffic bucket을 반환합니다.
    pub(crate) fn series(&self, since_ms: u64) -> Result<Vec<SeriesPoint>, StorageError> {
        self.rollup_series("traffic_rollups_1m", since_ms)
    }

    /// 지정한 시각 이후 상세 10초 traffic bucket을 반환합니다.
    pub(crate) fn ten_second_series(
        &self,
        since_ms: u64,
    ) -> Result<Vec<SeriesPoint>, StorageError> {
        self.rollup_series("traffic_rollups_10s", since_ms)
    }

    fn rollup_series(&self, table: &str, since_ms: u64) -> Result<Vec<SeriesPoint>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(&format!(
            "SELECT bucket_ms, SUM(requests), SUM(errors), SUM(throttled),
                    CAST(SUM(latency_sum_micros) / MAX(SUM(requests), 1) AS INTEGER),
                    SUM(request_body_bytes), SUM(response_body_bytes)
             FROM {table} WHERE bucket_ms >= ?1
             GROUP BY bucket_ms ORDER BY bucket_ms ASC"
        ))?;
        let rows = statement.query_map([to_i64(since_ms)], |row| {
            Ok(SeriesPoint {
                bucket_unix_ms: from_i64(row.get(0)?),
                requests: from_i64(row.get(1)?),
                errors: from_i64(row.get(2)?),
                throttled: from_i64(row.get(3)?),
                latency_avg_micros: from_i64(row.get(4)?),
                request_body_bytes: from_i64(row.get(5)?),
                response_body_bytes: from_i64(row.get(6)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 구조화 사건을 저장합니다.
    pub(crate) fn record_event(&self, event: &GuardEvent) -> Result<(), StorageError> {
        let payload = serde_json::to_string(event)?;
        self.lock().execute(
            "INSERT INTO guard_events(
                event_id, occurred_at, severity, kind, payload
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(event_id) DO UPDATE SET
                occurred_at = excluded.occurred_at,
                severity = excluded.severity,
                kind = excluded.kind,
                payload = excluded.payload",
            params![
                event.event_id,
                event.occurred_at,
                format!("{:?}", event.severity).to_ascii_lowercase(),
                event.kind,
                payload
            ],
        )?;
        Ok(())
    }

    /// notification 대상 사건을 event ID 기준으로 한 번만 등록합니다.
    pub(crate) fn register_notification(
        &self,
        event_id: &str,
        max_attempts: u8,
    ) -> Result<bool, StorageError> {
        let connection = self.lock();
        connection.execute(
            "INSERT OR IGNORE INTO notification_deliveries(event_id, status, attempts)
             VALUES (?1, 'pending', 0)",
            [event_id],
        )?;
        let record = connection.query_row(
            "SELECT attempts, status = 'delivered', status = 'failed'
             FROM notification_deliveries WHERE event_id = ?1",
            [event_id],
            |row| {
                Ok(NotificationDeliveryRecord {
                    attempts: u8::try_from(row.get::<_, u64>(0)?).unwrap_or(u8::MAX),
                    delivered: row.get(1)?,
                    exhausted: row.get(2)?,
                })
            },
        )?;
        Ok(!record.delivered && !record.exhausted && record.attempts < max_attempts)
    }

    /// network 전송 직전에 attempt를 영속 증가시킵니다.
    pub(crate) fn begin_notification_attempt(
        &self,
        event_id: &str,
        attempted_at: &str,
    ) -> Result<u8, StorageError> {
        let connection = self.lock();
        connection.execute(
            "UPDATE notification_deliveries
             SET status = 'delivering', attempts = attempts + 1, last_attempt_at = ?2
             WHERE event_id = ?1 AND status != 'delivered'",
            params![event_id, attempted_at],
        )?;
        let attempts = connection.query_row(
            "SELECT attempts FROM notification_deliveries WHERE event_id = ?1",
            [event_id],
            |row| row.get::<_, u64>(0),
        )?;
        Ok(u8::try_from(attempts).unwrap_or(u8::MAX))
    }

    /// 성공한 notification을 영속 완료 처리합니다.
    pub(crate) fn complete_notification(
        &self,
        event_id: &str,
        delivered_at: &str,
    ) -> Result<(), StorageError> {
        self.lock().execute(
            "UPDATE notification_deliveries
             SET status = 'delivered', delivered_at = ?2, last_error_code = NULL
             WHERE event_id = ?1",
            params![event_id, delivered_at],
        )?;
        Ok(())
    }

    /// 실패한 notification을 재시도 대기 또는 최종 실패로 기록합니다.
    pub(crate) fn fail_notification(
        &self,
        event_id: &str,
        failed_at: &str,
        error_code: &str,
        exhausted: bool,
    ) -> Result<(), StorageError> {
        self.lock().execute(
            "UPDATE notification_deliveries
             SET status = ?2, last_attempt_at = ?3, last_error_code = ?4
             WHERE event_id = ?1",
            params![
                event_id,
                if exhausted { "failed" } else { "pending" },
                failed_at,
                error_code
            ],
        )?;
        Ok(())
    }

    /// 재시작 뒤 이어서 보낼 bounded 미완료 사건을 반환합니다.
    pub(crate) fn pending_notifications(
        &self,
        max_attempts: u8,
        limit: usize,
    ) -> Result<Vec<GuardEvent>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT events.payload
             FROM notification_deliveries AS delivery
             JOIN guard_events AS events ON events.event_id = delivery.event_id
             WHERE delivery.status IN ('pending', 'delivering')
               AND delivery.attempts < ?1
             ORDER BY events.occurred_at ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![u64::from(max_attempts), to_i64(limit as u64)],
            |row| row.get::<_, String>(0),
        )?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    /// 영속 notification 전송 상태를 관리자 read-back 형태로 집계합니다.
    pub(crate) fn notification_summary(&self) -> Result<NotificationDeliverySummary, StorageError> {
        let connection = self.lock();
        let (delivered, failed, pending) = connection.query_row(
            "SELECT
                SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status IN ('pending', 'delivering') THEN 1 ELSE 0 END)
             FROM notification_deliveries",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<u64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<u64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<u64>>(2)?.unwrap_or(0),
                ))
            },
        )?;
        let last_success_at = connection
            .query_row(
                "SELECT delivered_at FROM notification_deliveries
                 WHERE delivered_at IS NOT NULL ORDER BY delivered_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let last_failure = connection
            .query_row(
                "SELECT last_attempt_at, last_error_code FROM notification_deliveries
                 WHERE last_error_code IS NOT NULL ORDER BY last_attempt_at DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                },
            )
            .optional()?;
        Ok(NotificationDeliverySummary {
            delivered,
            failed,
            pending,
            last_success_at,
            last_failure_at: last_failure.as_ref().and_then(|value| value.0.clone()),
            last_error_code: last_failure.and_then(|value| value.1),
        })
    }

    /// 최신 사건을 반환합니다.
    pub(crate) fn events(&self, limit: usize) -> Result<Vec<EventRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT event_id, occurred_at, severity, kind, payload
             FROM guard_events ORDER BY occurred_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([to_i64(limit as u64)], |row| {
            let payload: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                payload,
            ))
        })?;
        rows.map(|row| {
            let (event_id, occurred_at, severity, kind, payload) = row?;
            Ok(EventRow {
                event_id,
                occurred_at,
                severity,
                kind,
                payload: serde_json::from_str(&payload)?,
            })
        })
        .collect()
    }

    /// canonical request ID의 단기 상세를 반환합니다.
    pub(crate) fn request_trace(
        &self,
        request_id: &str,
    ) -> Result<Option<RequestTraceRow>, StorageError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT request_id, occurred_at_ms, method, route_class, normalized_route,
                        route_cost, status, latency_micros, request_body_bytes,
                        response_body_bytes, upstream_connection_reused, decision, policy_version,
                        bot_class, bot_provider, bot_verified, bot_reason, user_agent_family
                 FROM traffic_samples WHERE request_id = ?1 LIMIT 1",
                [request_id],
                |row| {
                    Ok(RequestTraceRow {
                        request_id: row.get(0)?,
                        occurred_at_unix_ms: from_i64(row.get(1)?),
                        method: row.get(2)?,
                        route_class: row.get(3)?,
                        normalized_route: row.get(4)?,
                        route_cost: from_i64(row.get(5)?).try_into().unwrap_or(u8::MAX),
                        status: from_i64(row.get(6)?).try_into().unwrap_or(u16::MAX),
                        latency_micros: from_i64(row.get(7)?),
                        request_body_bytes: from_i64(row.get(8)?),
                        response_body_bytes: from_i64(row.get(9)?),
                        upstream_connection_reused: row.get(10)?,
                        decision: row.get(11)?,
                        policy_version: from_i64(row.get(12)?),
                        bot_class: row.get(13)?,
                        bot_provider: row.get(14)?,
                        bot_verified: row.get(15)?,
                        bot_reason: row.get(16)?,
                        user_agent_family: row.get(17)?,
                    })
                },
            )
            .optional()?)
    }

    /// event ID 또는 event가 포함한 operation ID와 일치하는 bounded 사건을 반환합니다.
    pub(crate) fn events_for_correlation(
        &self,
        correlation_id: &str,
        limit: usize,
    ) -> Result<Vec<EventRow>, StorageError> {
        let operation_fragment = format!(
            "\"operation_id\":{}",
            serde_json::to_string(correlation_id)?
        );
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT event_id, occurred_at, severity, kind, payload
             FROM guard_events
             WHERE event_id = ?1
                OR event_id = 'action-' || ?1
                OR event_id = 'provider-' || ?1
                OR instr(payload, ?2) > 0
             ORDER BY occurred_at DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![correlation_id, operation_fragment, to_i64(limit as u64)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (event_id, occurred_at, severity, kind, payload) = row?;
            Ok(EventRow {
                event_id,
                occurred_at,
                severity,
                kind,
                payload: serde_json::from_str(&payload)?,
            })
        })
        .collect()
    }

    /// operation ID와 정확히 일치하는 감사 action을 반환합니다.
    pub(crate) fn audit_action(
        &self,
        operation_id: &str,
    ) -> Result<Option<AuditActionRow>, StorageError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT operation_id, occurred_at, action, mode, result
                 FROM audit_actions WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(AuditActionRow {
                        operation_id: row.get(0)?,
                        occurred_at: row.get(1)?,
                        action: row.get(2)?,
                        mode: row.get(3)?,
                        result: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// idempotency key의 기존 action과 mode를 확인합니다.
    pub(crate) fn completed_action(
        &self,
        operation_id: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        Ok(self
            .lock()
            .query_row(
                "SELECT action, mode FROM audit_actions WHERE operation_id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    /// 운영 action 감사를 영속화합니다.
    pub(crate) fn record_action(
        &self,
        operation_id: &str,
        occurred_at: &str,
        action: &str,
        mode: &str,
        result: &str,
    ) -> Result<(), StorageError> {
        self.lock().execute(
            "INSERT OR IGNORE INTO audit_actions(
                operation_id, occurred_at, action, mode, result
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![operation_id, occurred_at, action, mode, result],
        )?;
        Ok(())
    }

    /// 상세·IP·10초·1분·사건·감사 계층 retention을 bounded batch로 적용합니다.
    pub(crate) fn retain(&self, cutoffs: &RetentionCutoffs) -> Result<u64, StorageError> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        let mut deleted = 0_u64;
        deleted = deleted.saturating_add(execute_bounded_delete(
            &transaction,
            "traffic_samples",
            "occurred_at_ms",
            cutoffs.detail_since_ms,
        )?);
        let anonymized = transaction.execute(
            "UPDATE traffic_samples SET client_ip = NULL
             WHERE id IN (
                SELECT id FROM traffic_samples
                WHERE occurred_at_ms < ?1 AND client_ip IS NOT NULL
                LIMIT ?2
             )",
            params![
                to_i64(cutoffs.raw_ip_since_ms),
                to_i64(RETENTION_DELETE_LIMIT)
            ],
        )? as u64;
        deleted = deleted.saturating_add(execute_bounded_delete(
            &transaction,
            "traffic_client_rollups_1m",
            "bucket_ms",
            cutoffs.raw_ip_since_ms,
        )?);
        deleted = deleted.saturating_add(execute_bounded_delete(
            &transaction,
            "traffic_rollups_10s",
            "bucket_ms",
            cutoffs.detail_since_ms,
        )?);
        deleted = deleted.saturating_add(execute_bounded_delete(
            &transaction,
            "traffic_rollups_1m",
            "bucket_ms",
            cutoffs.aggregate_since_ms,
        )?);
        deleted = deleted.saturating_add(execute_bounded_delete(
            &transaction,
            "traffic_bot_rollups_1m",
            "bucket_ms",
            cutoffs.aggregate_since_ms,
        )?);
        deleted = deleted.saturating_add(transaction.execute(
            "DELETE FROM guard_events WHERE rowid IN (
                SELECT rowid FROM guard_events
                WHERE unixepoch(occurred_at) < ?1 LIMIT ?2
             )",
            params![
                to_i64(cutoffs.incident_since_seconds),
                to_i64(RETENTION_DELETE_LIMIT)
            ],
        )? as u64);
        deleted = deleted.saturating_add(transaction.execute(
            "DELETE FROM audit_actions WHERE rowid IN (
                SELECT rowid FROM audit_actions
                WHERE unixepoch(occurred_at) < ?1 LIMIT ?2
             )",
            params![
                to_i64(cutoffs.audit_since_seconds),
                to_i64(RETENTION_DELETE_LIMIT)
            ],
        )? as u64);
        transaction.commit()?;
        let retention_backlog = has_retention_backlog(&connection, cutoffs)?;
        connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_row| Ok(()))?;
        drop(connection);

        self.health
            .retention_deleted_rows
            .fetch_add(deleted, Ordering::Relaxed);
        self.health
            .retention_anonymized_rows
            .fetch_add(anonymized, Ordering::Relaxed);
        self.health
            .retention_backlog
            .store(retention_backlog, Ordering::Relaxed);
        self.health
            .last_retention_at_unix_ms
            .store(system_time_millis(), Ordering::Relaxed);
        self.refresh_health()?;
        Ok(deleted)
    }

    /// DB·WAL·reclaimable page와 filesystem 여유를 갱신합니다.
    pub(crate) fn refresh_health(&self) -> Result<(), StorageError> {
        let Some(database_path) = self.database_path.as_deref() else {
            return Ok(());
        };
        let database_bytes = file_size(database_path);
        let wal_bytes = file_size(&wal_path(database_path));
        let (page_count, freelist_count, page_size) = {
            let connection = self.lock();
            (
                pragma_u64(&connection, "page_count")?,
                pragma_u64(&connection, "freelist_count")?,
                pragma_u64(&connection, "page_size")?,
            )
        };
        let allocated_bytes = page_count.saturating_mul(page_size);
        let reclaimable_bytes = freelist_count.saturating_mul(page_size);
        let database_used_bytes = allocated_bytes.saturating_sub(reclaimable_bytes);
        let disk_available_bytes = database_path
            .parent()
            .and_then(|parent| rustix::fs::statvfs(parent).ok())
            .map(|stats| stats.f_bavail.saturating_mul(stats.f_frsize));
        let budget_exceeded =
            database_used_bytes.saturating_add(wal_bytes) >= self.health.max_database_bytes;
        let disk_space_low = disk_available_bytes
            .is_some_and(|available| available < self.health.min_disk_free_bytes);

        self.health
            .database_bytes
            .store(database_bytes, Ordering::Relaxed);
        self.health
            .database_used_bytes
            .store(database_used_bytes, Ordering::Relaxed);
        self.health
            .reclaimable_bytes
            .store(reclaimable_bytes, Ordering::Relaxed);
        self.health.wal_bytes.store(wal_bytes, Ordering::Relaxed);
        self.health.disk_available_bytes.store(
            disk_available_bytes.unwrap_or(UNKNOWN_DISK_BYTES),
            Ordering::Relaxed,
        );
        self.health
            .database_budget_exceeded
            .store(budget_exceeded, Ordering::Relaxed);
        self.health
            .disk_space_low
            .store(disk_space_low, Ordering::Relaxed);
        Ok(())
    }

    /// lock 없이 읽는 현재 저장소 health snapshot입니다.
    pub(crate) fn health(&self) -> StorageHealthSnapshot {
        self.health.snapshot()
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn apply_rollup_migration(connection: &mut Connection) -> Result<(), rusqlite::Error> {
    let applied = connection
        .query_row(
            "SELECT version FROM schema_migrations WHERE version = 2",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if applied {
        return Ok(());
    }
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE traffic_rollups_10s (
            bucket_ms INTEGER NOT NULL,
            normalized_route TEXT NOT NULL,
            route_class TEXT NOT NULL,
            requests INTEGER NOT NULL,
            errors INTEGER NOT NULL,
            throttled INTEGER NOT NULL,
            latency_sum_micros INTEGER NOT NULL,
            max_route_cost INTEGER NOT NULL,
            request_body_bytes INTEGER NOT NULL,
            response_body_bytes INTEGER NOT NULL,
            PRIMARY KEY(bucket_ms, normalized_route, route_class)
        );
        CREATE INDEX traffic_rollups_10s_time_idx ON traffic_rollups_10s(bucket_ms);
        CREATE TABLE traffic_rollups_1m (
            bucket_ms INTEGER NOT NULL,
            normalized_route TEXT NOT NULL,
            route_class TEXT NOT NULL,
            requests INTEGER NOT NULL,
            errors INTEGER NOT NULL,
            throttled INTEGER NOT NULL,
            latency_sum_micros INTEGER NOT NULL,
            max_route_cost INTEGER NOT NULL,
            request_body_bytes INTEGER NOT NULL,
            response_body_bytes INTEGER NOT NULL,
            PRIMARY KEY(bucket_ms, normalized_route, route_class)
        );
        CREATE INDEX traffic_rollups_1m_time_idx ON traffic_rollups_1m(bucket_ms);
        CREATE TABLE traffic_client_rollups_1m (
            bucket_ms INTEGER NOT NULL,
            client_ip TEXT NOT NULL,
            requests INTEGER NOT NULL,
            throttled INTEGER NOT NULL,
            denied INTEGER NOT NULL,
            request_body_bytes INTEGER NOT NULL,
            response_body_bytes INTEGER NOT NULL,
            last_seen_ms INTEGER NOT NULL,
            PRIMARY KEY(bucket_ms, client_ip)
        );
        CREATE INDEX traffic_client_rollups_time_idx
            ON traffic_client_rollups_1m(bucket_ms);
        CREATE INDEX traffic_client_rollups_ip_idx
            ON traffic_client_rollups_1m(client_ip);",
    )?;
    backfill_route_rollup(&transaction, "traffic_rollups_10s", TEN_SECONDS_MS)?;
    backfill_route_rollup(&transaction, "traffic_rollups_1m", MINUTE_MS)?;
    transaction.execute(
        "INSERT INTO traffic_client_rollups_1m(
            bucket_ms, client_ip, requests, throttled, denied,
            request_body_bytes, response_body_bytes, last_seen_ms
         )
         SELECT (occurred_at_ms / 60000) * 60000, client_ip, COUNT(*),
                SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END),
                SUM(request_body_bytes), SUM(response_body_bytes), MAX(occurred_at_ms)
         FROM traffic_samples WHERE client_ip IS NOT NULL
         GROUP BY occurred_at_ms / 60000, client_ip",
        [],
    )?;
    transaction.execute("INSERT INTO schema_migrations(version) VALUES (2)", [])?;
    transaction.commit()
}

fn apply_correlation_migration(connection: &mut Connection) -> Result<(), rusqlite::Error> {
    let applied = connection
        .query_row(
            "SELECT version FROM schema_migrations WHERE version = 3",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if applied {
        return Ok(());
    }
    ensure_column(connection, "request_id", "TEXT")?;
    ensure_column(connection, "method", "TEXT NOT NULL DEFAULT ''")?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS traffic_request_id_idx
            ON traffic_samples(request_id) WHERE request_id IS NOT NULL;
         INSERT INTO schema_migrations(version) VALUES (3);",
    )?;
    transaction.commit()
}

fn apply_bot_telemetry_migration(connection: &mut Connection) -> Result<(), rusqlite::Error> {
    let applied = connection
        .query_row(
            "SELECT version FROM schema_migrations WHERE version = 4",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if applied {
        return Ok(());
    }
    ensure_column(
        connection,
        "bot_class",
        "TEXT NOT NULL DEFAULT 'undeclared'",
    )?;
    ensure_column(connection, "bot_provider", "TEXT")?;
    ensure_column(connection, "bot_verified", "INTEGER NOT NULL DEFAULT 0")?;
    ensure_column(
        connection,
        "bot_reason",
        "TEXT NOT NULL DEFAULT 'not_declared'",
    )?;
    ensure_column(
        connection,
        "user_agent_family",
        "TEXT NOT NULL DEFAULT 'missing'",
    )?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE traffic_bot_rollups_1m (
            bucket_ms INTEGER NOT NULL,
            bot_class TEXT NOT NULL,
            bot_provider TEXT NOT NULL,
            bot_verified INTEGER NOT NULL,
            bot_reason TEXT NOT NULL,
            user_agent_family TEXT NOT NULL,
            requests INTEGER NOT NULL,
            denied INTEGER NOT NULL,
            throttled INTEGER NOT NULL,
            response_body_bytes INTEGER NOT NULL,
            PRIMARY KEY(
                bucket_ms, bot_class, bot_provider, bot_verified, bot_reason, user_agent_family
            )
        );
        CREATE INDEX traffic_bot_rollups_time_idx
            ON traffic_bot_rollups_1m(bucket_ms);
        INSERT INTO schema_migrations(version) VALUES (4);",
    )?;
    transaction.commit()
}

fn backfill_route_rollup(
    transaction: &Transaction<'_>,
    table: &str,
    bucket_ms: u64,
) -> Result<(), rusqlite::Error> {
    transaction.execute(
        &format!(
            "INSERT INTO {table}(
                bucket_ms, normalized_route, route_class, requests, errors, throttled,
                latency_sum_micros, max_route_cost, request_body_bytes, response_body_bytes
             )
             SELECT (occurred_at_ms / ?1) * ?1, normalized_route, route_class, COUNT(*),
                    SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                    SUM(latency_micros), MAX(route_cost),
                    SUM(request_body_bytes), SUM(response_body_bytes)
             FROM traffic_samples
             GROUP BY occurred_at_ms / ?1, normalized_route, route_class"
        ),
        [to_i64(bucket_ms)],
    )?;
    Ok(())
}

fn add_route_rollup(
    values: &mut HashMap<RouteRollupKey, RouteRollupValue>,
    telemetry: &TelemetryEnvelope,
    bucket_width_ms: u64,
) {
    let key = RouteRollupKey {
        bucket_unix_ms: bucket(telemetry.occurred_at_unix_ms, bucket_width_ms),
        normalized_route: telemetry.normalized_route.clone(),
        route_class: telemetry.route_class.clone(),
    };
    let value = values.entry(key).or_default();
    value.requests = value.requests.saturating_add(1);
    value.errors = value
        .errors
        .saturating_add(u64::from(telemetry.status >= 500));
    value.throttled = value
        .throttled
        .saturating_add(u64::from(telemetry.decision == "throttle"));
    value.latency_sum_micros = value
        .latency_sum_micros
        .saturating_add(telemetry.latency_micros);
    value.max_route_cost = value.max_route_cost.max(telemetry.route_cost);
    value.request_body_bytes = value
        .request_body_bytes
        .saturating_add(telemetry.request_body_bytes);
    value.response_body_bytes = value
        .response_body_bytes
        .saturating_add(telemetry.response_body_bytes);
}

fn upsert_route_rollups(
    transaction: &Transaction<'_>,
    table: &str,
    rollups: &HashMap<RouteRollupKey, RouteRollupValue>,
) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare_cached(&format!(
        "INSERT INTO {table}(
            bucket_ms, normalized_route, route_class, requests, errors, throttled,
            latency_sum_micros, max_route_cost, request_body_bytes, response_body_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(bucket_ms, normalized_route, route_class) DO UPDATE SET
            requests = requests + excluded.requests,
            errors = errors + excluded.errors,
            throttled = throttled + excluded.throttled,
            latency_sum_micros = latency_sum_micros + excluded.latency_sum_micros,
            max_route_cost = MAX(max_route_cost, excluded.max_route_cost),
            request_body_bytes = request_body_bytes + excluded.request_body_bytes,
            response_body_bytes = response_body_bytes + excluded.response_body_bytes"
    ))?;
    for (key, value) in rollups {
        statement.execute(params![
            to_i64(key.bucket_unix_ms),
            key.normalized_route,
            key.route_class,
            to_i64(value.requests),
            to_i64(value.errors),
            to_i64(value.throttled),
            to_i64(value.latency_sum_micros),
            value.max_route_cost,
            to_i64(value.request_body_bytes),
            to_i64(value.response_body_bytes),
        ])?;
    }
    Ok(())
}

fn upsert_client_rollups(
    transaction: &Transaction<'_>,
    rollups: &HashMap<ClientRollupKey, ClientRollupValue>,
) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO traffic_client_rollups_1m(
            bucket_ms, client_ip, requests, throttled, denied,
            request_body_bytes, response_body_bytes, last_seen_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(bucket_ms, client_ip) DO UPDATE SET
            requests = requests + excluded.requests,
            throttled = throttled + excluded.throttled,
            denied = denied + excluded.denied,
            request_body_bytes = request_body_bytes + excluded.request_body_bytes,
            response_body_bytes = response_body_bytes + excluded.response_body_bytes,
            last_seen_ms = MAX(last_seen_ms, excluded.last_seen_ms)",
    )?;
    for (key, value) in rollups {
        statement.execute(params![
            to_i64(key.bucket_unix_ms),
            key.client_ip,
            to_i64(value.requests),
            to_i64(value.throttled),
            to_i64(value.denied),
            to_i64(value.request_body_bytes),
            to_i64(value.response_body_bytes),
            to_i64(value.last_seen_unix_ms),
        ])?;
    }
    Ok(())
}

fn upsert_bot_rollups(
    transaction: &Transaction<'_>,
    rollups: &HashMap<BotRollupKey, BotRollupValue>,
) -> Result<(), rusqlite::Error> {
    let mut statement = transaction.prepare_cached(
        "INSERT INTO traffic_bot_rollups_1m(
            bucket_ms, bot_class, bot_provider, bot_verified, bot_reason,
            user_agent_family, requests, denied, throttled, response_body_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(
            bucket_ms, bot_class, bot_provider, bot_verified, bot_reason, user_agent_family
         ) DO UPDATE SET
            requests = requests + excluded.requests,
            denied = denied + excluded.denied,
            throttled = throttled + excluded.throttled,
            response_body_bytes = response_body_bytes + excluded.response_body_bytes",
    )?;
    for (key, value) in rollups {
        statement.execute(params![
            to_i64(key.bucket_unix_ms),
            key.bot_class,
            key.bot_provider,
            key.bot_verified,
            key.bot_reason,
            key.user_agent_family,
            to_i64(value.requests),
            to_i64(value.denied),
            to_i64(value.throttled),
            to_i64(value.response_body_bytes),
        ])?;
    }
    Ok(())
}

fn execute_bounded_delete(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
    cutoff: u64,
) -> Result<u64, rusqlite::Error> {
    Ok(transaction.execute(
        &format!(
            "DELETE FROM {table} WHERE rowid IN (
                SELECT rowid FROM {table} WHERE {column} < ?1 LIMIT ?2
             )"
        ),
        params![to_i64(cutoff), to_i64(RETENTION_DELETE_LIMIT)],
    )? as u64)
}

fn has_retention_backlog(
    connection: &Connection,
    cutoffs: &RetentionCutoffs,
) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT CASE WHEN
            EXISTS(SELECT 1 FROM traffic_samples WHERE occurred_at_ms < ?1 LIMIT 1)
            OR EXISTS(SELECT 1 FROM traffic_samples
                      WHERE occurred_at_ms < ?2 AND client_ip IS NOT NULL LIMIT 1)
            OR EXISTS(SELECT 1 FROM traffic_client_rollups_1m WHERE bucket_ms < ?2 LIMIT 1)
            OR EXISTS(SELECT 1 FROM traffic_rollups_10s WHERE bucket_ms < ?1 LIMIT 1)
            OR EXISTS(SELECT 1 FROM traffic_rollups_1m WHERE bucket_ms < ?3 LIMIT 1)
            OR EXISTS(SELECT 1 FROM traffic_bot_rollups_1m WHERE bucket_ms < ?3 LIMIT 1)
            OR EXISTS(SELECT 1 FROM guard_events WHERE unixepoch(occurred_at) < ?4 LIMIT 1)
            OR EXISTS(SELECT 1 FROM audit_actions WHERE unixepoch(occurred_at) < ?5 LIMIT 1)
        THEN 1 ELSE 0 END",
        params![
            to_i64(cutoffs.detail_since_ms),
            to_i64(cutoffs.raw_ip_since_ms),
            to_i64(cutoffs.aggregate_since_ms),
            to_i64(cutoffs.incident_since_seconds),
            to_i64(cutoffs.audit_since_seconds),
        ],
        |row| row.get::<_, bool>(0),
    )
}

fn pragma_u64(connection: &Connection, name: &str) -> Result<u64, rusqlite::Error> {
    connection.query_row(&format!("PRAGMA {name}"), [], |row| {
        row.get::<_, i64>(0).map(from_i64)
    })
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn wal_path(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push("-wal");
    PathBuf::from(value)
}

fn bucket(value: u64, width: u64) -> u64 {
    value.saturating_sub(value % width)
}

fn hours_to_millis(hours: u64) -> u64 {
    hours.saturating_mul(60).saturating_mul(60_000)
}

fn days_to_millis(days: u64) -> u64 {
    days.saturating_mul(24).saturating_mul(60 * 60_000)
}

fn to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn from_i64(value: i64) -> u64 {
    value.max(0) as u64
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn system_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn atomic_saturating_decrement(value: &AtomicU64) {
    let _result = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

fn ensure_column(
    connection: &Connection,
    name: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('traffic_samples') WHERE name = ?1",
        [name],
        |row| row.get(0),
    )?;
    if count == 0 {
        connection.execute_batch(&format!(
            "ALTER TABLE traffic_samples ADD COLUMN {name} {definition}"
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use guard_core::{GuardEvent, Severity};

    use super::{RetentionCutoffs, SqliteStore};
    use crate::telemetry::TelemetryEnvelope;

    fn telemetry(
        occurred_at_unix_ms: u64,
        client_ip: Option<IpAddr>,
        decision: &str,
    ) -> TelemetryEnvelope {
        TelemetryEnvelope {
            schema_version: 1,
            request_id: format!("guard-{occurred_at_unix_ms}"),
            method: "GET".to_owned(),
            route_class: "strict".to_owned(),
            normalized_route: "/bbs/:id".to_owned(),
            route_cost: 4,
            status: if decision == "deny" { 503 } else { 429 },
            latency_micros: 900,
            client_ip,
            request_body_bytes: 0,
            response_body_bytes: 256,
            upstream_connection_reused: Some(false),
            decision: decision.to_owned(),
            policy_version: 2,
            occurred_at_unix_ms,
            ..TelemetryEnvelope::default()
        }
    }

    fn notification_event(event_id: &str) -> GuardEvent {
        GuardEvent {
            schema_version: 1,
            event_id: event_id.to_owned(),
            occurred_at: "2026-07-23T00:00:00Z".to_owned(),
            severity: Severity::Critical,
            kind: "provider.action_failed".to_owned(),
            summary: "Provider 조치가 실패했습니다.".to_owned(),
            reason_codes: Vec::new(),
            evidence: BTreeMap::new(),
            action: BTreeMap::new(),
            result: BTreeMap::new(),
            recovery: BTreeMap::new(),
        }
    }

    #[test]
    fn notification_delivery_is_deduplicated_and_resumable()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        let event = notification_event("event-notification-1");
        store.record_event(&event)?;

        assert!(store.register_notification(&event.event_id, 3)?);
        assert!(store.register_notification(&event.event_id, 3)?);
        assert_eq!(
            store.begin_notification_attempt(&event.event_id, "2026-07-23T00:00:01Z")?,
            1
        );
        store.fail_notification(
            &event.event_id,
            "2026-07-23T00:00:02Z",
            "WEBHOOK_TIMEOUT",
            false,
        )?;
        assert_eq!(store.pending_notifications(3, 16)?, vec![event.clone()]);

        assert_eq!(
            store.begin_notification_attempt(&event.event_id, "2026-07-23T00:00:03Z")?,
            2
        );
        store.complete_notification(&event.event_id, "2026-07-23T00:00:04Z")?;
        store.record_event(&event)?;
        assert!(!store.register_notification(&event.event_id, 3)?);
        assert!(store.pending_notifications(3, 16)?.is_empty());
        let summary = store.notification_summary()?;
        assert_eq!(summary.delivered, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(
            summary.last_success_at.as_deref(),
            Some("2026-07-23T00:00:04Z")
        );
        Ok(())
    }

    #[test]
    fn persists_batch_and_aggregates_independent_rollups() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SqliteStore::in_memory()?;
        let client = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        store.record_traffic_batch(&[
            telemetry(120_000, client, "throttle"),
            telemetry(125_000, client, "deny"),
            telemetry(181_000, client, "allow"),
        ])?;

        let clients = store.clients(10)?;
        assert_eq!(clients[0].requests, 3);
        assert_eq!(clients[0].throttled, 1);
        assert_eq!(clients[0].denied, 1);
        let routes = store.routes(10)?;
        assert_eq!(routes[0].requests, 3);
        assert_eq!(routes[0].errors, 1);
        let series = store.series(0)?;
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].bucket_unix_ms, 120_000);
        assert_eq!(series[0].requests, 2);
        let ten_second_series = store.ten_second_series(0)?;
        assert_eq!(ten_second_series.len(), 2);
        assert_eq!(ten_second_series[0].requests, 2);
        let ten_second_rows: i64 =
            store
                .lock()
                .query_row("SELECT COUNT(*) FROM traffic_rollups_10s", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(ten_second_rows, 2);
        assert_eq!(store.health().persisted_batches, 1);
        Ok(())
    }

    #[test]
    fn persists_and_finds_bounded_request_trace() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        let mut telemetry = telemetry(120_000, None, "deny");
        telemetry.bot_class = guard_core::BotClass::SpoofedCrawler;
        telemetry.bot_provider = Some(guard_core::CrawlerProvider::Google);
        telemetry.bot_reason = guard_core::BotReason::OfficialNetworkMismatch;
        telemetry.user_agent_family = guard_core::UserAgentFamily::Googlebot;
        let request_id = telemetry.request_id.clone();
        store.record_traffic(&telemetry)?;

        let trace = store
            .request_trace(&request_id)?
            .ok_or("request trace was not persisted")?;
        assert_eq!(trace.request_id, request_id);
        assert_eq!(trace.method, "GET");
        assert_eq!(trace.normalized_route, "/bbs/:id");
        assert_eq!(trace.status, 503);
        assert_eq!(trace.decision, "deny");
        assert_eq!(trace.bot_class, "spoofed_crawler");
        assert_eq!(trace.bot_provider.as_deref(), Some("google"));
        let bots = store.bots(10)?;
        assert_eq!(bots.len(), 1);
        assert_eq!(bots[0].requests, 1);
        assert_eq!(bots[0].denied, 1);
        assert_eq!(bots[0].user_agent_family, "googlebot");
        assert!(store.request_trace("guard-missing")?.is_none());
        Ok(())
    }

    #[test]
    fn correlates_operation_audit_and_event_without_scanning_request_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        store.record_action(
            "operation-42",
            "2026-07-16T00:00:00Z",
            "manual_hold",
            "manual_hold",
            "applied",
        )?;
        store.record_event(&GuardEvent {
            schema_version: 1,
            event_id: "provider-failed-random".to_owned(),
            occurred_at: "2026-07-16T00:00:01Z".to_owned(),
            severity: Severity::Critical,
            kind: "provider.action_failed".to_owned(),
            summary: "Provider 조치가 실패했습니다.".to_owned(),
            reason_codes: Vec::new(),
            evidence: BTreeMap::from([("operation_id".to_owned(), "operation-42".to_owned())]),
            action: BTreeMap::new(),
            result: BTreeMap::new(),
            recovery: BTreeMap::new(),
        })?;

        let action = store
            .audit_action("operation-42")?
            .ok_or("audit action was not correlated")?;
        assert_eq!(action.action, "manual_hold");
        let events = store.events_for_correlation("operation-42", 10)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "provider-failed-random");
        Ok(())
    }

    #[test]
    fn client_detail_reports_bounded_routes_scores_errors_and_actions()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        let client = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)));
        let mut throttled = telemetry(1_000, client, "throttle");
        throttled.status = 429;
        throttled.request_body_bytes = 10;
        throttled.response_body_bytes = 20;
        let mut denied = telemetry(2_000, client, "deny");
        denied.normalized_route = "/api/login".to_owned();
        denied.route_cost = 9;
        denied.status = 503;
        denied.request_body_bytes = 30;
        denied.response_body_bytes = 40;
        let other = telemetry(
            3_000,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
            "allow",
        );
        store.record_traffic_batch(&[throttled, denied, other])?;

        let detail = store
            .client_detail("203.0.113.8", 8)?
            .ok_or("client detail missing")?;
        assert_eq!(detail.requests, 2);
        assert_eq!(detail.errors, 1);
        assert_eq!(detail.throttled, 1);
        assert_eq!(detail.denied, 1);
        assert_eq!(detail.max_route_cost, 9);
        assert_eq!(detail.last_decision, "deny");
        assert_eq!(detail.last_seen_unix_ms, 2_000);
        assert_eq!(detail.request_body_bytes, 40);
        assert_eq!(detail.response_body_bytes, 60);
        assert_eq!(detail.routes.len(), 2);
        assert_eq!(detail.routes[0].normalized_route, "/api/login");
        assert_eq!(detail.routes[0].errors, 1);
        assert_eq!(detail.routes[0].denied, 1);
        assert!(store.client_detail("192.0.2.44", 8)?.is_none());
        Ok(())
    }

    #[test]
    fn retention_applies_each_storage_layer_independently() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SqliteStore::in_memory()?;
        let client = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        store.record_traffic_batch(&[
            telemetry(60_000, client, "allow"),
            telemetry(120_000, client, "allow"),
            telemetry(180_000, client, "allow"),
        ])?;

        let deleted = store.retain(&RetentionCutoffs::new(150_000, 100_000, 90_000, 0, 0))?;

        assert!(deleted >= 4);
        assert_eq!(store.clients(10)?[0].requests, 2);
        let series = store.series(0)?;
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].bucket_unix_ms, 120_000);
        assert!(store.health().last_retention_at_unix_ms.is_some());
        Ok(())
    }

    #[test]
    fn zero_day_ip_policy_never_persists_client_identifiers()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::from_connection(
            rusqlite::Connection::open_in_memory()?,
            None,
            u64::MAX,
            0,
            false,
        )?;
        store.record_traffic(&telemetry(
            120_000,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "allow",
        ))?;

        assert!(store.clients(10)?.is_empty());
        let stored_ip_count: i64 = store.lock().query_row(
            "SELECT COUNT(*) FROM traffic_samples WHERE client_ip IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(stored_ip_count, 0);
        Ok(())
    }

    #[test]
    fn retention_reports_ip_anonymization_separately_from_deletion()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        let client = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        store.record_traffic_batch(&[
            telemetry(60_000, client, "allow"),
            telemetry(120_000, client, "allow"),
        ])?;

        let deleted = store.retain(&RetentionCutoffs::new(0, 150_000, 0, 0, 0))?;
        let health = store.health();
        assert_eq!(health.retention_anonymized_rows, 2);
        assert!(deleted >= 2);
        assert!(!health.retention_backlog);
        let stored_ip_count: i64 = store.lock().query_row(
            "SELECT COUNT(*) FROM traffic_samples WHERE client_ip IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(stored_ip_count, 0);
        Ok(())
    }

    #[test]
    fn retention_bounds_incident_and_audit_tables() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        store.lock().execute_batch(
            "INSERT INTO guard_events(event_id, occurred_at, severity, kind, payload) VALUES
                ('old-event', '1970-01-01T00:01:00Z', 'info', 'old', '{}'),
                ('new-event', '1970-01-01T00:05:00Z', 'info', 'new', '{}');
             INSERT INTO audit_actions(operation_id, occurred_at, action, mode, result) VALUES
                ('old-action', '1970-01-01T00:01:00Z', 'old', 'normal', 'ok'),
                ('new-action', '1970-01-01T00:05:00Z', 'new', 'normal', 'ok');",
        )?;

        store.retain(&RetentionCutoffs::new(0, 0, 0, 200, 200))?;

        let connection = store.lock();
        let event_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM guard_events", [], |row| row.get(0))?;
        let audit_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM audit_actions", [], |row| row.get(0))?;
        assert_eq!(event_count, 1);
        assert_eq!(audit_count, 1);
        Ok(())
    }

    #[test]
    fn migration_backfills_existing_version_one_samples() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             INSERT INTO schema_migrations(version) VALUES (1);
             CREATE TABLE traffic_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at_ms INTEGER NOT NULL,
                client_ip TEXT,
                route_class TEXT NOT NULL,
                normalized_route TEXT NOT NULL,
                route_cost INTEGER NOT NULL,
                status INTEGER NOT NULL,
                latency_micros INTEGER NOT NULL,
                request_body_bytes INTEGER NOT NULL DEFAULT 0,
                response_body_bytes INTEGER NOT NULL DEFAULT 0,
                upstream_connection_reused INTEGER,
                decision TEXT NOT NULL,
                policy_version INTEGER NOT NULL
             );
             INSERT INTO traffic_samples(
                occurred_at_ms, client_ip, route_class, normalized_route, route_cost,
                status, latency_micros, request_body_bytes, response_body_bytes,
                upstream_connection_reused, decision, policy_version
             ) VALUES (
                61234, '127.0.0.1', 'general', '/legacy', 2,
                200, 100, 0, 32, 1, 'allow', 1
             );",
        )?;

        let store = SqliteStore::from_connection(connection, None, u64::MAX, 0, true)?;

        assert_eq!(store.series(0)?[0].bucket_unix_ms, 60_000);
        assert_eq!(store.ten_second_series(0)?[0].bucket_unix_ms, 60_000);
        assert_eq!(store.clients(10)?[0].client_ip, "127.0.0.1");
        let migration: i64 = store.lock().query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version IN (2, 3)",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(migration, 2);
        assert!(store.request_trace("guard-legacy")?.is_none());
        Ok(())
    }

    #[test]
    fn queue_and_writer_loss_are_visible_without_unbounded_depth()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        store.note_queue_send_started();
        store.note_queue_send_failed();
        store.note_queue_dequeued();
        store.note_write_failure(3);

        let health = store.health();
        assert_eq!(health.queue_depth, 0);
        assert_eq!(health.queue_dropped_samples, 1);
        assert_eq!(health.write_dropped_samples, 3);
        assert_eq!(health.write_failures, 1);
        assert_eq!(health.condition, super::StorageCondition::Degraded);
        Ok(())
    }
}
