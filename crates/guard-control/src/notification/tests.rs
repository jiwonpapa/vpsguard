//! Notification retry·dedupe·payload 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use guard_core::config::NotificationConfig;
use guard_core::{GuardEvent, Severity};
use reqwest::StatusCode;
use tokio::sync::mpsc;

use super::{
    DeliveryError, NotificationBackend, NotificationHandle, NotificationInitError,
    NotificationWorker, RuntimeMetrics, WebhookPayload, should_notify,
};
use crate::storage::SqliteStore;

struct FakeBackend {
    responses: Mutex<VecDeque<Result<(), DeliveryError>>>,
    calls: AtomicU64,
}

impl FakeBackend {
    fn new(responses: impl IntoIterator<Item = Result<(), DeliveryError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: AtomicU64::new(0),
        }
    }
}

impl NotificationBackend for FakeBackend {
    fn send(&self, _event: &GuardEvent) -> Result<(), DeliveryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .unwrap_or(Ok(()))
    }
}

fn event(event_id: &str, kind: &str, mode: Option<&str>) -> GuardEvent {
    GuardEvent {
        schema_version: 1,
        event_id: event_id.to_owned(),
        occurred_at: "2026-07-23T00:00:00Z".to_owned(),
        severity: Severity::Critical,
        kind: kind.to_owned(),
        summary: "외부 알림에 필요한 bounded 요약입니다.".to_owned(),
        reason_codes: Vec::new(),
        evidence: BTreeMap::from([(
            "must_not_leave_server".to_owned(),
            "private-evidence".to_owned(),
        )]),
        action: mode
            .map(|mode| BTreeMap::from([("mode".to_owned(), mode.to_owned())]))
            .unwrap_or_default(),
        result: BTreeMap::new(),
        recovery: BTreeMap::new(),
    }
}

fn worker(
    backend: Arc<FakeBackend>,
    storage: Arc<SqliteStore>,
    max_attempts: u8,
) -> NotificationWorker {
    let (_sender, receiver) = mpsc::channel(16);
    NotificationWorker {
        receiver,
        backend,
        storage,
        metrics: Arc::new(RuntimeMetrics::default()),
        max_attempts,
        initial_backoff: Duration::from_millis(1),
    }
}

#[tokio::test]
async fn transient_failure_retries_then_persists_success() -> Result<(), Box<dyn std::error::Error>>
{
    let storage = Arc::new(SqliteStore::in_memory()?);
    let event = event(
        "notification-retry",
        "provider.transaction",
        Some("EmergencyProxy"),
    );
    storage.record_event(&event)?;
    let backend = Arc::new(FakeBackend::new([Err(DeliveryError::Timeout), Ok(())]));

    worker(Arc::clone(&backend), Arc::clone(&storage), 3)
        .deliver(&event)
        .await;

    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
    let summary = storage.notification_summary()?;
    assert_eq!(summary.delivered, 1);
    assert_eq!(summary.failed, 0);
    assert!(summary.last_success_at.is_some());
    Ok(())
}

#[tokio::test]
async fn delivered_event_id_is_not_sent_twice() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStore::in_memory()?);
    let event = event(
        "notification-dedupe",
        "provider.transaction",
        Some("EmergencyProxy"),
    );
    storage.record_event(&event)?;
    let backend = Arc::new(FakeBackend::new([Ok(())]));
    let worker = worker(Arc::clone(&backend), Arc::clone(&storage), 3);

    worker.deliver(&event).await;
    worker.deliver(&event).await;

    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    assert_eq!(storage.notification_summary()?.delivered, 1);
    Ok(())
}

#[tokio::test]
async fn terminal_http_failure_is_bounded_and_visible() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStore::in_memory()?);
    let event = event("notification-rejected", "provider.action_failed", None);
    storage.record_event(&event)?;
    let backend = Arc::new(FakeBackend::new([Err(DeliveryError::Http(
        StatusCode::BAD_REQUEST,
    ))]));

    worker(Arc::clone(&backend), Arc::clone(&storage), 3)
        .deliver(&event)
        .await;

    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
    let summary = storage.notification_summary()?;
    assert_eq!(summary.failed, 1);
    assert_eq!(
        summary.last_error_code.as_deref(),
        Some("WEBHOOK_HTTP_REJECTED")
    );
    Ok(())
}

#[test]
fn only_major_transitions_and_provider_events_leave_the_server() {
    assert!(should_notify(&event(
        "local",
        "guard.mode_transition",
        Some("LocalGuard")
    )));
    assert!(should_notify(&event(
        "recovery",
        "guard.mode_transition",
        Some("RecoveryReady")
    )));
    assert!(should_notify(&event(
        "provider",
        "provider.transaction_started",
        None
    )));
    assert!(!should_notify(&event(
        "watch",
        "guard.mode_transition",
        Some("Watch")
    )));
    assert!(!should_notify(&event(
        "operator",
        "operator.action",
        Some("ManualHold")
    )));
}

#[test]
fn webhook_payload_excludes_internal_evidence_and_recovery_maps()
-> Result<(), Box<dyn std::error::Error>> {
    let event = event(
        "notification-payload",
        "provider.action_failed",
        Some("EmergencyProxy"),
    );
    let encoded = serde_json::to_string(&WebhookPayload::from_event(&event))?;

    assert!(encoded.contains("notification-payload"));
    assert!(!encoded.contains("must_not_leave_server"));
    assert!(!encoded.contains("private-evidence"));
    Ok(())
}

#[test]
fn initialization_failure_stays_visible_without_rejecting_the_event_producer()
-> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStore::in_memory()?);
    let event = event("notification-degraded", "provider.action_failed", None);
    storage.record_event(&event)?;
    let config = NotificationConfig {
        enabled: true,
        webhook_url: Some("https://alerts.example.test/vpsguard".to_owned()),
        ..NotificationConfig::default()
    };
    let handle = NotificationHandle::unavailable(
        &config,
        Arc::clone(&storage),
        &NotificationInitError::Client,
    );

    handle.enqueue(&event);

    let status = handle.status();
    assert_eq!(status.queue_dropped, 1);
    assert_eq!(status.pending, 1);
    assert_eq!(
        status.last_error_code.as_deref(),
        Some("NOTIFICATION_CLIENT_UNAVAILABLE")
    );
    Ok(())
}
