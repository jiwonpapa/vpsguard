//! Control 관리 Host, session, CSRF와 idempotency 회귀 테스트입니다.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use guard_agent::cgroup::CgroupSnapshot;
use guard_agent::services::ServiceSemanticSnapshot;
use guard_agent::{CollectorHealth, CollectorState};
use guard_core::config::UiConfig;
use guard_core::{GuardMode, GuardState};
use guard_system::{AtomicJsonStore, inspect_tls_management};
use tokio::sync::{RwLock, broadcast};
use tower::ServiceExt;

use super::{AppState, ProviderActionLease, router};
use crate::auth::{BootstrapStore, IssuedSession, SessionStore, UiAccessPolicy};
use crate::storage::SqliteStore;
use crate::telemetry::{TelemetryEnvelope, TrafficAggregator};

const LOOPBACK_HOST: &str = "127.0.0.1:7727";
const LOOPBACK_ORIGIN: &str = "http://127.0.0.1:7727";

fn app(path: &std::path::Path) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    app_with_public_host(path, None)
}

fn app_with_public_host(
    path: &std::path::Path,
    public_host: Option<&str>,
) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    app_with_options(
        path,
        public_host,
        guard_core::config::TlsManagementMode::Auto,
    )
}

fn app_with_options(
    path: &std::path::Path,
    public_host: Option<&str>,
    tls_plan_mode: guard_core::config::TlsManagementMode,
) -> Result<Arc<AppState>, Box<dyn std::error::Error>> {
    let (events, _) = broadcast::channel(32);
    let ui = UiConfig {
        bind: LOOPBACK_HOST.parse()?,
        public_host: public_host.map(ToOwned::to_owned),
        admin_socket: "/tmp/vps-guard-admin-test.sock".into(),
        login_rate_limit_rpm: 10,
        language: "ko".to_owned(),
    };
    Ok(Arc::new(AppState {
        state: RwLock::new(GuardState::normal("2026-07-14T00:00:00Z")),
        state_store: AtomicJsonStore::new(path),
        traffic: Mutex::new(TrafficAggregator::new(10)),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        tls_management: RwLock::new(inspect_tls_management(
            &guard_core::config::TlsConfig::default(),
        )),
        tls_plan_mode,
        tls_plan_domains: vec!["example.test".to_owned()],
        bootstrap: BootstrapStore::new(),
        completed_actions: Mutex::new(VecDeque::new()),
        storage: Arc::new(SqliteStore::in_memory()?),
        events,
        sessions: SessionStore::new(),
        access: UiAccessPolicy::from_config(&ui),
        provider: Arc::new(Mutex::new(None)),
        provider_action_active: Arc::new(AtomicBool::new(false)),
    }))
}

fn session_cookie(issued: &IssuedSession) -> &str {
    issued
        .set_cookie
        .split(';')
        .next()
        .unwrap_or(issued.set_cookie.as_str())
}

fn action_request(
    path: &str,
    operation_id: &str,
    issued: &IssuedSession,
) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header("host", LOOPBACK_HOST)
        .header("origin", LOOPBACK_ORIGIN)
        .header("cookie", session_cookie(issued))
        .header("x-csrf-token", &issued.csrf_token)
        .header("idempotency-key", operation_id)
        .body(Body::empty())
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
async fn anonymous_read_and_mutation_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let read = router(Arc::clone(&state))
        .oneshot(
            Request::get("/api/v1/status")
                .header("host", LOOPBACK_HOST)
                .body(Body::empty())?,
        )
        .await?;
    let mutation = router(state)
        .oneshot(
            Request::post("/api/v1/actions/manual-hold")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("x-vpsguard-token", "legacy-token-must-not-authorize")
                .header("idempotency-key", "operation-1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(read.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(mutation.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn login_code_is_single_use_and_issues_session() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = state
        .bootstrap
        .issue(Duration::from_secs(300))
        .ok_or("code issue failed")?;
    let body = serde_json::json!({ "login_code": issued.code }).to_string();
    let request = || {
        Request::post("/api/v1/session")
            .header("host", LOOPBACK_HOST)
            .header("origin", LOOPBACK_ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
    };
    let first = router(Arc::clone(&state)).oneshot(request()?).await?;
    let second = router(state).oneshot(request()?).await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert!(first.headers().contains_key("set-cookie"));
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn wrong_host_and_origin_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = state
        .bootstrap
        .issue(Duration::from_secs(300))
        .ok_or("code issue failed")?;
    let body = serde_json::json!({ "login_code": issued.code }).to_string();
    let wrong_host = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/session")
                .header("host", "evil.example")
                .header("origin", LOOPBACK_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))?,
        )
        .await?;
    let wrong_origin = router(state)
        .oneshot(
            Request::post("/api/v1/session")
                .header("host", LOOPBACK_HOST)
                .header("origin", "https://evil.example")
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(wrong_host.status(), StatusCode::BAD_REQUEST);
    assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn public_https_session_cookie_is_secure() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app_with_public_host(
        &directory.path().join("state.json"),
        Some("guard.example.com"),
    )?;
    let issued = state
        .bootstrap
        .issue(Duration::from_secs(300))
        .ok_or("code issue failed")?;
    let response = router(state)
        .oneshot(
            Request::post("/api/v1/session")
                .header("host", "guard.example.com")
                .header("origin", "https://guard.example.com")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "login_code": issued.code }).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .ok_or("set-cookie missing")?;
    assert!(cookie.contains("; Secure"));
    assert!(cookie.contains("; HttpOnly"));
    assert!(cookie.contains("; SameSite=Strict"));
    Ok(())
}

#[tokio::test]
async fn existing_cookie_restores_csrf_without_a_new_login_code()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = state.sessions.issue(false);
    let response = router(state)
        .oneshot(
            Request::get("/api/v1/session")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4_096).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body)?["csrf_token"],
        issued.csrf_token
    );
    Ok(())
}

#[tokio::test]
async fn csrf_and_origin_are_required_after_session_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = state.sessions.issue(false);
    let response = router(state)
        .oneshot(
            Request::post("/api/v1/actions/manual-hold")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .header("idempotency-key", "operation-no-csrf")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn tls_assisted_plan_requires_mode_and_returns_no_apply_command()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app_with_options(
        &directory.path().join("state.json"),
        None,
        guard_core::config::TlsManagementMode::VpsguardAssisted,
    )?;
    let issued = state.sessions.issue(false);
    let response = router(state)
        .oneshot(
            Request::post("/api/v1/tls/assisted-plan")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("cookie", session_cookie(&issued))
                .header("x-csrf-token", &issued.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"email":"admin@example.test"}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 8_192).await?;
    let json = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(json["requires_explicit_approval"], true);
    assert!(json.get("command").is_none());
    assert_eq!(json["steps"][0], "verify_dns");
    Ok(())
}

#[tokio::test]
async fn duplicate_action_is_not_applied_twice() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = state.sessions.issue(false);
    let first = router(Arc::clone(&state))
        .oneshot(action_request(
            "/api/v1/actions/manual-hold",
            "operation-1",
            &issued,
        )?)
        .await?;
    let second = router(Arc::clone(&state))
        .oneshot(action_request(
            "/api/v1/actions/manual-hold",
            "operation-1",
            &issued,
        )?)
        .await?;
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
    let issued = state.sessions.issue(false);
    let first = router(Arc::clone(&state))
        .oneshot(action_request(
            "/api/v1/actions/manual-hold",
            "operation-conflict",
            &issued,
        )?)
        .await?;
    let second = router(state)
        .oneshot(action_request(
            "/api/v1/actions/resume-auto",
            "operation-conflict",
            &issued,
        )?)
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
    let issued = state.sessions.issue(false);
    let response = router(Arc::clone(&state))
        .oneshot(action_request(
            "/api/v1/actions/emergency-proxy",
            "provider-1",
            &issued,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.state.read().await.current_mode, GuardMode::Normal);
    let events = state.storage.events(10)?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "provider.action_failed");
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
        .oneshot(
            Request::get("/api/v1/clients")
                .header("host", LOOPBACK_HOST)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let issued = state.sessions.issue(false);
    let authenticated = router(state)
        .oneshot(
            Request::get("/api/v1/clients")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
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

#[tokio::test]
async fn resources_exposes_bounded_storage_health_to_authenticated_session()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    state.storage.note_queue_send_started();
    state.storage.note_queue_send_failed();
    state.service_health.write().await.push(CollectorHealth {
        name: "php_fpm".to_owned(),
        state: CollectorState::Live,
        last_success_at: Some("2026-07-14T00:00:00Z".to_owned()),
        error_code: None,
        unit: Some("php8.3-fpm.service".to_owned()),
        collected_at_unix_ms: Some(1_000),
        resource_state: Some(CollectorState::Live),
        semantic_state: Some(CollectorState::Live),
        resource_error_code: None,
        semantic_error_code: None,
        resources: Some(CgroupSnapshot {
            collected_at_unix_ms: 1_000,
            cpu_usage_usec: 500,
            cpu_user_usec: 400,
            cpu_system_usec: 100,
            cpu_nr_throttled: 0,
            cpu_throttled_usec: 0,
            cpu_usage_milli_percent: Some(12_500),
            memory_current_bytes: 4_096,
            memory_peak_bytes: Some(8_192),
            memory_high_events: 0,
            memory_max_events: 0,
            oom_events: 0,
            oom_kill_events: 0,
            io_read_bytes: 10,
            io_write_bytes: 20,
            process_count: 2,
            task_count: 4,
        }),
        semantic: Some(ServiceSemanticSnapshot::PhpFpm {
            accepted_connections: 10,
            listen_queue: 1,
            max_listen_queue: 2,
            listen_queue_length: 128,
            idle_processes: 2,
            active_processes: 1,
            total_processes: 3,
            max_active_processes: 2,
            max_children_reached: 0,
            slow_requests: 0,
        }),
    });
    let issued = state.sessions.issue(false);
    let response = router(state)
        .oneshot(
            Request::get("/api/v1/resources")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16_384).await?;
    let value = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(value["storage"]["queue_capacity"], 4_096);
    assert_eq!(value["storage"]["queue_dropped_samples"], 1);
    assert_eq!(value["storage"]["condition"], "degraded");
    assert_eq!(
        value["services"][0]["resources"]["memory_current_bytes"],
        4_096
    );
    assert_eq!(value["services"][0]["semantic"]["kind"], "php_fpm");
    assert_eq!(value["services"][0]["semantic"]["listen_queue"], 1);
    Ok(())
}

#[tokio::test]
async fn traffic_series_selects_one_second_ten_second_and_minute_layers()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let telemetry = TelemetryEnvelope {
        schema_version: 1,
        request_id: "request-series".to_owned(),
        method: "GET".to_owned(),
        route_class: "general".to_owned(),
        normalized_route: "/health".to_owned(),
        route_cost: 1,
        status: 200,
        latency_micros: 50,
        client_ip: None,
        request_body_bytes: 0,
        response_body_bytes: 4,
        upstream_connection_reused: Some(true),
        decision: "allow".to_owned(),
        policy_version: 1,
        occurred_at_unix_ms: 61_234,
    };
    state
        .traffic
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ingest(&telemetry);
    state.storage.record_traffic(&telemetry)?;
    let issued = state.sessions.issue(false);

    for (resolution, expected_bucket) in [("1s", 61_000), ("10s", 60_000), ("1m", 60_000)] {
        let response = router(Arc::clone(&state))
            .oneshot(
                Request::get(format!(
                    "/api/v1/traffic/series?resolution={resolution}&since_unix_ms=0"
                ))
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16_384).await?;
        let value = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(value["items"][0]["bucket_unix_ms"], expected_bucket);
    }
    Ok(())
}
