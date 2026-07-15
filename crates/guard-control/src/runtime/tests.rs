//! Control 정책 lease 갱신 회귀 테스트입니다.

use std::time::{Duration, Instant};

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use guard_core::GuardMode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use super::{POLICY_REFRESH_INTERVAL, build_policy, policy_renewal_due, storage_writer_loop};
use crate::storage::{SqliteStore, TRAFFIC_QUEUE_CAPACITY};
use crate::telemetry::TelemetryEnvelope;

#[test]
fn policy_refresh_is_due_before_the_ten_minute_lease_expires() {
    let now = Instant::now();
    assert!(policy_renewal_due(None, now));
    assert!(!policy_renewal_due(
        Some(now - Duration::from_secs(4 * 60)),
        now
    ));
    assert!(policy_renewal_due(Some(now - POLICY_REFRESH_INTERVAL), now));
}

#[test]
fn generated_policy_keeps_a_ten_minute_bounded_lease() -> Result<(), Box<dyn std::error::Error>> {
    let policy = build_policy(GuardMode::LocalGuard, 8, 1_024, 100)?;
    let generated = OffsetDateTime::parse(&policy.generated_at, &Rfc3339)?;
    let expires = OffsetDateTime::parse(&policy.expires_at, &Rfc3339)?;
    assert_eq!(expires - generated, time::Duration::minutes(10));
    Ok(())
}

#[test]
fn dedicated_writer_drains_queue_as_one_transaction_batch() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(SqliteStore::in_memory()?);
    let (sender, mut receiver) = mpsc::channel(TRAFFIC_QUEUE_CAPACITY);
    for occurred_at_unix_ms in [1_000, 1_001, 1_002] {
        store.note_queue_send_started();
        sender.try_send(TelemetryEnvelope {
            schema_version: 1,
            request_id: format!("writer-{occurred_at_unix_ms}"),
            method: "GET".to_owned(),
            route_class: "general".to_owned(),
            normalized_route: "/health".to_owned(),
            route_cost: 1,
            status: 200,
            latency_micros: 50,
            client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            request_body_bytes: 0,
            response_body_bytes: 4,
            upstream_connection_reused: Some(true),
            decision: "allow".to_owned(),
            policy_version: 1,
            occurred_at_unix_ms,
        })?;
    }
    drop(sender);

    storage_writer_loop(Arc::clone(&store), &mut receiver);

    let health = store.health();
    assert_eq!(health.queue_depth, 0);
    assert_eq!(health.persisted_samples, 3);
    assert_eq!(health.persisted_batches, 1);
    Ok(())
}
