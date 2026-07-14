//! control API authorization과 idempotency 회귀 테스트입니다.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use guard_core::{GuardMode, GuardState};
use guard_system::AtomicJsonStore;
use tokio::sync::{RwLock, broadcast};
use tower::ServiceExt;

use super::{AppState, ProviderActionLease, router};
use crate::auth::SessionStore;
use crate::storage::SqliteStore;
use crate::telemetry::{TelemetryEnvelope, TrafficAggregator};

fn app(path: &std::path::Path) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    let (events, _) = broadcast::channel(32);
    Ok(Arc::new(AppState {
        state: RwLock::new(GuardState::normal("2026-07-14T00:00:00Z")),
        state_store: AtomicJsonStore::new(path),
        traffic: Mutex::new(TrafficAggregator::new(10)),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        action_token: "test-token".to_owned(),
        completed_actions: Mutex::new(VecDeque::new()),
        storage: Arc::new(SqliteStore::in_memory()?),
        events,
        sessions: SessionStore::new(),
        provider: Arc::new(Mutex::new(None)),
        provider_action_active: Arc::new(AtomicBool::new(false)),
    }))
}

#[test]
fn provider_actions_are_exclusive() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let first = ProviderActionLease::acquire(&state).ok_or("first lease unavailable")?;
    assert!(ProviderActionLease::acquire(&state).is_none());
    drop(first);
    assert!(ProviderActionLease::acquire(&state).is_some());
    Ok(())
}

#[tokio::test]
async fn mutation_requires_action_token() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let response = router(app(&directory.path().join("state.json"))?)
        .oneshot(
            Request::post("/api/v1/actions/manual-hold")
                .header("idempotency-key", "operation-1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn duplicate_action_is_not_applied_twice() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let request = || {
        Request::post("/api/v1/actions/manual-hold")
            .header("idempotency-key", "operation-1")
            .header("x-vpsguard-token", "test-token")
            .body(Body::empty())
    };
    let first = router(Arc::clone(&state)).oneshot(request()?).await?;
    let second = router(Arc::clone(&state)).oneshot(request()?).await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(state.state.read().await.current_mode, GuardMode::ManualHold);
    assert_eq!(
        state
            .completed_actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn reused_key_for_different_action_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let first = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/actions/manual-hold")
                .header("idempotency-key", "operation-conflict")
                .header("x-vpsguard-token", "test-token")
                .body(Body::empty())?,
        )
        .await?;
    let second = router(state)
        .oneshot(
            Request::post("/api/v1/actions/resume-auto")
                .header("idempotency-key", "operation-conflict")
                .header("x-vpsguard-token", "test-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
async fn unconfigured_provider_fails_without_changing_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/actions/emergency-proxy")
                .header("idempotency-key", "provider-1")
                .header("x-vpsguard-token", "test-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.state.read().await.current_mode, GuardMode::Normal);
    Ok(())
}

#[tokio::test]
async fn client_ip_requires_authenticated_session() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    state.storage.record_traffic(&TelemetryEnvelope {
        schema_version: 1,
        request_id: "request-1".to_owned(),
        method: "GET".to_owned(),
        route_class: "general".to_owned(),
        normalized_route: "/health".to_owned(),
        route_cost: 1,
        status: 200,
        latency_micros: 50,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))),
        request_body_bytes: 0,
        response_body_bytes: 4,
        upstream_connection_reused: Some(false),
        decision: "allow".to_owned(),
        policy_version: 1,
        occurred_at_unix_ms: 1_000,
    })?;

    let anonymous = router(Arc::clone(&state))
        .oneshot(Request::get("/api/v1/clients").body(Body::empty())?)
        .await?;
    let anonymous_body = to_bytes(anonymous.into_body(), 8_192).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&anonymous_body)?["items"][0]["client_ip"],
        "203.0.113.0/24"
    );

    let issued = state.sessions.issue(false);
    let authenticated = router(state)
        .oneshot(
            Request::get("/api/v1/clients")
                .header("cookie", issued.set_cookie)
                .body(Body::empty())?,
        )
        .await?;
    let authenticated_body = to_bytes(authenticated.into_body(), 8_192).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&authenticated_body)?["items"][0]["client_ip"],
        "203.0.113.8"
    );
    Ok(())
}
