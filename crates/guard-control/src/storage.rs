//! SQLite WAL 기반 bounded traffic, 사건과 감사 저장소입니다.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use guard_core::GuardEvent;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use thiserror::Error;

use crate::telemetry::TelemetryEnvelope;

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

/// traffic 시계열 bucket입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SeriesPoint {
    pub(crate) bucket_unix_ms: u64,
    pub(crate) requests: u64,
    pub(crate) errors: u64,
    pub(crate) throttled: u64,
    pub(crate) latency_avg_micros: u64,
    pub(crate) request_body_bytes: u64,
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

/// connection 한 개를 mutex로 보호하는 소형 VPS용 SQLite 저장소입니다.
#[derive(Debug)]
pub(crate) struct SqliteStore {
    connection: Mutex<Connection>,
}

impl SqliteStore {
    /// WAL database를 열고 migration을 적용합니다.
    pub(crate) fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StorageError> {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS traffic_samples (
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
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// telemetry 한 건을 privacy-safe column으로 저장합니다.
    pub(crate) fn record_traffic(&self, telemetry: &TelemetryEnvelope) -> Result<(), StorageError> {
        self.lock().execute(
            "INSERT INTO traffic_samples(
                occurred_at_ms, client_ip, route_class, normalized_route, route_cost,
                status, latency_micros, request_body_bytes, response_body_bytes,
                upstream_connection_reused, decision, policy_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                to_i64(telemetry.occurred_at_unix_ms),
                telemetry.client_ip.map(|value| value.to_string()),
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
            ],
        )?;
        Ok(())
    }

    /// 최근 client aggregate를 반환합니다.
    pub(crate) fn clients(&self, limit: usize) -> Result<Vec<ClientRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT client_ip, COUNT(*),
                    SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END),
                    SUM(request_body_bytes), SUM(response_body_bytes),
                    MAX(occurred_at_ms)
             FROM traffic_samples WHERE client_ip IS NOT NULL
             GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT ?1",
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

    /// 최근 route aggregate를 반환합니다.
    pub(crate) fn routes(&self, limit: usize) -> Result<Vec<RouteRow>, StorageError> {
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT normalized_route, route_class, COUNT(*),
                    SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                    CAST(AVG(latency_micros) AS INTEGER), MAX(route_cost),
                    SUM(request_body_bytes), SUM(response_body_bytes)
             FROM traffic_samples GROUP BY normalized_route, route_class
             ORDER BY COUNT(*) DESC LIMIT ?1",
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

    /// 지정한 시각 이후 1분 traffic bucket을 반환합니다.
    pub(crate) fn series(&self, since_ms: u64) -> Result<Vec<SeriesPoint>, StorageError> {
        const MINUTE_MS: i64 = 60_000;
        let connection = self.lock();
        let mut statement = connection.prepare(
            "SELECT (occurred_at_ms / 60000) * 60000, COUNT(*),
                    SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN decision = 'throttle' THEN 1 ELSE 0 END),
                    CAST(AVG(latency_micros) AS INTEGER),
                    SUM(request_body_bytes), SUM(response_body_bytes)
             FROM traffic_samples WHERE occurred_at_ms >= ?1
             GROUP BY occurred_at_ms / 60000 ORDER BY 1 ASC",
        )?;
        let rows = statement.query_map([to_i64(since_ms)], |row| {
            let bucket: i64 = row.get(0)?;
            Ok(SeriesPoint {
                bucket_unix_ms: from_i64(bucket.saturating_sub(bucket % MINUTE_MS)),
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
            "INSERT OR REPLACE INTO guard_events(
                event_id, occurred_at, severity, kind, payload
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
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

    /// detail traffic와 raw IP 보존기간을 적용합니다.
    pub(crate) fn retain_since(
        &self,
        detail_since_ms: u64,
        raw_ip_since_ms: u64,
    ) -> Result<(), StorageError> {
        let mut connection = self.lock();
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM traffic_samples WHERE occurred_at_ms < ?1",
            [to_i64(detail_since_ms)],
        )?;
        transaction.execute(
            "UPDATE traffic_samples SET client_ip = NULL
             WHERE occurred_at_ms < ?1 AND client_ip IS NOT NULL",
            [to_i64(raw_ip_since_ms)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn from_i64(value: i64) -> u64 {
    value.max(0) as u64
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
    use std::net::{IpAddr, Ipv4Addr};

    use super::SqliteStore;
    use crate::telemetry::TelemetryEnvelope;

    #[test]
    fn persists_and_aggregates_privacy_safe_traffic() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::in_memory()?;
        store.record_traffic(&TelemetryEnvelope {
            schema_version: 1,
            request_id: "guard-1".to_owned(),
            method: "GET".to_owned(),
            route_class: "strict".to_owned(),
            normalized_route: "/bbs/:id".to_owned(),
            route_cost: 4,
            status: 429,
            latency_micros: 900,
            client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            request_body_bytes: 0,
            response_body_bytes: 256,
            upstream_connection_reused: Some(false),
            decision: "throttle".to_owned(),
            policy_version: 2,
            occurred_at_unix_ms: 120_000,
        })?;

        assert_eq!(store.clients(10)?[0].throttled, 1);
        assert_eq!(store.routes(10)?[0].normalized_route, "/bbs/:id");
        assert_eq!(store.series(0)?[0].bucket_unix_ms, 120_000);
        Ok(())
    }
}
