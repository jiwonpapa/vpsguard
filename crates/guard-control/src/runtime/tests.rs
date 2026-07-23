//! Control 정책 lease 갱신 회귀 테스트입니다.

use std::time::{Duration, Instant};

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use guard_core::{DetectionInput, Detector, GuardMode, GuardState};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;

use super::{
    POLICY_REFRESH_INTERVAL, build_policy, keep_emergency, keep_local_guard, policy_renewal_due,
    storage_writer_loop, transition_event, update_incident,
};
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
            ..TelemetryEnvelope::default()
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

#[test]
fn provider_failure_fallbacks_preserve_the_previous_transition_time() {
    let mut current = GuardState::normal("2026-07-22T00:00:00Z");
    current.current_mode = GuardMode::LocalGuard;
    let mut next = current.clone();
    next.current_mode = GuardMode::EmergencyProxy;
    next.last_transition_at = "2026-07-22T00:00:05Z".to_owned();

    keep_local_guard(&current, &mut next);
    assert_eq!(next.current_mode, GuardMode::LocalGuard);
    assert_eq!(next.last_transition_at, current.last_transition_at);

    current.current_mode = GuardMode::EmergencyProxy;
    next.current_mode = GuardMode::Recovering;
    next.last_transition_at = "2026-07-22T00:00:10Z".to_owned();
    keep_emergency(&current, &mut next);
    assert_eq!(next.current_mode, GuardMode::EmergencyProxy);
    assert_eq!(next.last_transition_at, current.last_transition_at);
}

#[test]
fn incident_and_transition_event_keep_bounded_explanations() {
    let previous = GuardState::normal("2026-07-22T00:00:00Z");
    let mut next = previous.clone();
    next.current_mode = GuardMode::LocalGuard;
    next.policy_version = 7;
    update_incident(&mut next);
    assert!(
        next.active_incident_id
            .as_deref()
            .is_some_and(|id| id.starts_with("incident-"))
    );

    let assessment = Detector::assess(&DetectionInput {
        trust: 0,
        automation: 95,
        route_cost: 90,
        upstream_pressure: 90,
        resource_signals_available: true,
        session_continuity: false,
        crawler_verified: false,
    });
    let event = transition_event(
        &previous,
        &next,
        &assessment,
        "2026-07-22T00:00:05Z".to_owned(),
    );
    assert_eq!(event.kind, "guard.mode_transition");
    assert_eq!(event.result["policy_version"], "7");
    assert!(!event.reason_codes.is_empty());

    next.current_mode = GuardMode::Normal;
    update_incident(&mut next);
    assert!(next.active_incident_id.is_none());
}
