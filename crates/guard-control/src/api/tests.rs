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
use guard_core::config::{
    AdminAuthProvider, DetectionMode, InspectionMode, SecurityConfig, UiConfig, UiTlsTermination,
};
use guard_core::correlation::is_valid_request_id;
use guard_core::{GuardMode, GuardState};
use guard_system::{AtomicJsonStore, inspect_tls_management};
use tokio::sync::{RwLock, broadcast};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

use super::{AppState, ProviderActionLease, router};
use crate::auth::{
    AuthError, BootstrapStore, IssuedSession, SessionStore, UiAccessPolicy, unix_seconds,
};
use crate::firewall::FirewallManager;
use crate::protection::ProtectionPolicyManager;
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
        public_port: 443,
        tls_termination: UiTlsTermination::Edge,
        auth_provider: AdminAuthProvider::Local,
        pam_service: "vps-guard".to_owned(),
        pam_allowed_group: "vpsguard-admin".to_owned(),
        admin_socket: "/tmp/vps-guard-admin-test.sock".into(),
        privileged_socket: "/tmp/vps-guard-privileged-test.sock".into(),
        login_rate_limit_rpm: 10,
        language: "ko".to_owned(),
    };
    Ok(Arc::new(AppState {
        state: RwLock::new(GuardState::normal("2026-07-14T00:00:00Z")),
        state_store: AtomicJsonStore::new(path),
        traffic: Mutex::new(TrafficAggregator::new(10)),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        inspection_mode: InspectionMode::Profiled,
        detection_mode: DetectionMode::Observe,
        security: SecurityConfig::default(),
        waf: guard_core::config::WafConfig::default(),
        tls_management: RwLock::new(inspect_tls_management(
            &guard_core::config::TlsConfig::default(),
        )),
        tls_plan_mode,
        tls_plan_domains: vec!["example.test".to_owned()],
        bootstrap: BootstrapStore::new(),
        completed_actions: Mutex::new(VecDeque::new()),
        storage: Arc::new(SqliteStore::in_memory()?),
        events,
        notification: crate::notification::NotificationHandle::disabled(Arc::new(
            SqliteStore::in_memory()?,
        )),
        protection: Arc::new(ProtectionPolicyManager::load(
            path.with_extension("policy.json"),
            0,
            GuardMode::Normal,
            1_048_576,
            10,
        )?),
        policy_operation: tokio::sync::Mutex::new(()),
        sessions: Arc::new(SessionStore::in_memory(10)?),
        access: UiAccessPolicy::from_config(&ui),
        firewall: Arc::new(FirewallManager::system(
            guard_core::config::FirewallMode::Disabled,
            22,
            "/tmp/vps-guard-privileged-test.sock".into(),
        )),
        provider: Arc::new(Mutex::new(None)),
        provider_action_active: Arc::new(AtomicBool::new(false)),
        request_ids: guard_core::correlation::RequestIdGenerator::new(),
    }))
}

fn session_cookie(issued: &IssuedSession) -> &str {
    issued
        .set_cookie
        .split(';')
        .next()
        .unwrap_or(issued.set_cookie.as_str())
}

fn issue_session(state: &AppState) -> Result<IssuedSession, AuthError> {
    state.sessions.issue_break_glass(false, unix_seconds()?)
}

fn enrollment_totp(
    secret_base32: &str,
    username: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let secret = Secret::Encoded(secret_base32.to_owned()).to_bytes()?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("VPSGuard".to_owned()),
        username.to_owned(),
    )?;
    Ok(totp.generate(u64::try_from(unix_seconds()?)?))
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

fn json_mutation_request(
    path: &str,
    issued: &IssuedSession,
    operation_id: Option<&str>,
    body: serde_json::Value,
) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::post(path)
        .header("host", LOOPBACK_HOST)
        .header("origin", LOOPBACK_ORIGIN)
        .header("cookie", session_cookie(issued))
        .header("x-csrf-token", &issued.csrf_token)
        .header("content-type", "application/json");
    if let Some(operation_id) = operation_id {
        request = request.header("idempotency-key", operation_id);
    }
    request.body(Body::from(body.to_string()))
}

fn protection_settings(local_strict_requests_per_minute: u32) -> serde_json::Value {
    serde_json::json!({
        "watch_strict_requests_per_minute": 120,
        "local_strict_requests_per_minute": local_strict_requests_per_minute,
        "local_upload_requests_per_minute": 15,
        "emergency_strict_requests_per_minute": 10,
        "emergency_upload_requests_per_minute": 5
    })
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
async fn control_assigns_valid_request_id_and_preserves_trusted_edge_id()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let trusted = "guard-0123456789abcdef0123456789abcdef-0000000000000001";
    let preserved = router(Arc::clone(&state))
        .oneshot(
            Request::get("/health/live")
                .header("host", LOOPBACK_HOST)
                .header("x-request-id", trusted)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(preserved.headers()["x-request-id"], trusted);

    let replaced = router(state)
        .oneshot(
            Request::get("/health/live")
                .header("host", LOOPBACK_HOST)
                .header("x-request-id", "client-controlled")
                .body(Body::empty())?,
        )
        .await?;
    let assigned = replaced.headers()["x-request-id"].to_str()?;
    assert!(is_valid_request_id(assigned));
    assert_ne!(assigned, "client-controlled");
    Ok(())
}

#[tokio::test]
async fn api_error_contains_cause_event_id_and_request_correlation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let response = router(app(&directory.path().join("state.json"))?)
        .oneshot(
            Request::get("/api/v1/status")
                .header("host", LOOPBACK_HOST)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(is_valid_request_id(
        response.headers()["x-request-id"].to_str()?
    ));
    let body = to_bytes(response.into_body(), 8_192).await?;
    let value = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert!(
        value["error"]["cause"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert!(
        value["error"]["event_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("error-"))
    );
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
    let issued = issue_session(&state)?;
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
async fn status_exposes_the_active_inspection_mode() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut state = app(&directory.path().join("state.json"))?;
    Arc::get_mut(&mut state)
        .ok_or("exclusive app state unavailable")?
        .inspection_mode = InspectionMode::ProtocolOnly;
    let issued = issue_session(&state)?;
    let response = router(state)
        .oneshot(
            Request::get("/api/v1/status")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4_096).await?;
    let json = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(json["inspection"], "protocol_only");
    assert_eq!(json["security"]["app_layer_active"], false);
    assert_eq!(json["security"]["csp_mode"], "off");
    assert_eq!(
        json["security"]["auth_rate_limit_rpm"],
        serde_json::Value::Null
    );
    assert_eq!(json["notification"]["enabled"], false);
    assert_eq!(json["notification"]["storage_available"], true);
    Ok(())
}

#[tokio::test]
async fn status_explains_recovery_ready_without_disabling_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    state.state.write().await.current_mode = GuardMode::RecoveryReady;
    let issued = issue_session(&state)?;
    let response = router(state)
        .oneshot(
            Request::get("/api/v1/status")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4_096).await?;
    let json = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(json["mode"], "RECOVERY_READY");
    assert!(
        json["reasons"][0]
            .as_str()
            .is_some_and(|reason| reason.contains("관리자 승인"))
    );
    Ok(())
}

#[tokio::test]
async fn status_exposes_effective_application_security_posture()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut state = app(&directory.path().join("state.json"))?;
    let mutable = Arc::get_mut(&mut state).ok_or("exclusive app state unavailable")?;
    mutable.detection_mode = DetectionMode::Enforce;
    mutable.security.csp_mode = guard_core::config::CspMode::Enforce;
    mutable.security.hsts_max_age_seconds = 86_400;
    mutable.security.auth_rate_limit_rpm = 6;
    let issued = issue_session(&state)?;
    let response = router(state)
        .oneshot(
            Request::get("/api/v1/status")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    let body = to_bytes(response.into_body(), 4_096).await?;
    let json = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(json["security"]["app_layer_active"], true);
    assert_eq!(json["security"]["csp_mode"], "enforce");
    assert_eq!(json["security"]["hsts_max_age_seconds"], 86_400);
    assert_eq!(json["security"]["auth_rate_limit_rpm"], 6);
    Ok(())
}

#[tokio::test]
async fn delegated_firewall_is_visible_and_rejects_mutation_without_ufw()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut state = app(&directory.path().join("state.json"))?;
    Arc::get_mut(&mut state)
        .ok_or("exclusive app state unavailable")?
        .firewall = Arc::new(FirewallManager::system(
        guard_core::config::FirewallMode::JwAgentDelegated,
        22,
        "/tmp/vps-guard-privileged-test.sock".into(),
    ));
    let issued = issue_session(&state)?;
    let status = router(Arc::clone(&state))
        .oneshot(
            Request::get("/api/v1/firewall")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status.status(), StatusCode::OK);
    let body = to_bytes(status.into_body(), 4_096).await?;
    let json = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(json["mode"], "jw_agent_delegated");
    assert_eq!(json["backend"], "jw-agent");
    assert_eq!(json["mutable"], false);

    let response = router(state)
        .oneshot(
            Request::post("/api/v1/firewall/plan")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("cookie", session_cookie(&issued))
                .header("x-csrf-token", &issued.csrf_token)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"kind":"add","rule":{"id":"web","action":"allow","source":null,"destination_port":443,"protocol":"tcp"}}"#,
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4_096).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body)?["error"]["code"],
        "FIREWALL_OWNERSHIP_DELEGATED"
    );
    Ok(())
}

#[tokio::test]
async fn csrf_and_origin_are_required_after_session_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = issue_session(&state)?;
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
    let issued = issue_session(&state)?;
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
async fn protection_settings_plan_apply_duplicate_and_edge_readback_work()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = issue_session(&state)?;

    let current = router(Arc::clone(&state))
        .oneshot(
            Request::get("/api/v1/settings/protection")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(current.status(), StatusCode::OK);
    let current =
        serde_json::from_slice::<serde_json::Value>(&to_bytes(current.into_body(), 8_192).await?)?;
    assert_eq!(current["policy_version"], 0);
    assert_eq!(current["edge_readback"], "pending");
    assert_eq!(current["enforcement_active"], false);

    let settings = protection_settings(29);
    let planned = router(Arc::clone(&state))
        .oneshot(json_mutation_request(
            "/api/v1/settings/protection/plan",
            &issued,
            None,
            serde_json::json!({"settings": settings}),
        )?)
        .await?;
    assert_eq!(planned.status(), StatusCode::OK);
    let planned =
        serde_json::from_slice::<serde_json::Value>(&to_bytes(planned.into_body(), 8_192).await?)?;
    assert_eq!(
        planned["changes"][0]["field"],
        "local_strict_requests_per_minute"
    );
    assert_eq!(planned["next_policy_version"], 1);

    let apply_body = serde_json::json!({
        "settings": protection_settings(29),
        "current_fingerprint": planned["current_fingerprint"],
        "plan_hash": planned["plan_hash"]
    });
    let applied = router(Arc::clone(&state))
        .oneshot(json_mutation_request(
            "/api/v1/settings/protection/apply",
            &issued,
            Some("protection-operation-1"),
            apply_body.clone(),
        )?)
        .await?;
    assert_eq!(applied.status(), StatusCode::OK);
    let applied =
        serde_json::from_slice::<serde_json::Value>(&to_bytes(applied.into_body(), 8_192).await?)?;
    assert_eq!(applied["applied"], true);
    assert_eq!(applied["policy_version"], 1);
    assert_eq!(state.state.read().await.policy_version, 1);

    let duplicate = router(Arc::clone(&state))
        .oneshot(json_mutation_request(
            "/api/v1/settings/protection/apply",
            &issued,
            Some("protection-operation-1"),
            apply_body,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::OK);
    let duplicate = serde_json::from_slice::<serde_json::Value>(
        &to_bytes(duplicate.into_body(), 8_192).await?,
    )?;
    assert_eq!(duplicate["applied"], false);
    assert_eq!(duplicate["policy_version"], 1);

    state.storage.record_traffic(&TelemetryEnvelope {
        request_id: "protection-readback".to_owned(),
        policy_version: 1,
        occurred_at_unix_ms: 1,
        ..TelemetryEnvelope::default()
    })?;
    let observed = router(state)
        .oneshot(
            Request::get("/api/v1/settings/protection")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    let observed =
        serde_json::from_slice::<serde_json::Value>(&to_bytes(observed.into_body(), 8_192).await?)?;
    assert_eq!(observed["edge_observed_policy_version"], 1);
    assert_eq!(observed["edge_readback"], "observed");
    Ok(())
}

#[tokio::test]
async fn protection_settings_reject_invalid_and_stale_plans_without_overwrite()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = issue_session(&state)?;

    let invalid = router(Arc::clone(&state))
        .oneshot(json_mutation_request(
            "/api/v1/settings/protection/plan",
            &issued,
            None,
            serde_json::json!({"settings": protection_settings(9)}),
        )?)
        .await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let mut plans = Vec::new();
    for local_strict in [29, 28] {
        let response = router(Arc::clone(&state))
            .oneshot(json_mutation_request(
                "/api/v1/settings/protection/plan",
                &issued,
                None,
                serde_json::json!({"settings": protection_settings(local_strict)}),
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        plans.push(serde_json::from_slice::<serde_json::Value>(
            &to_bytes(response.into_body(), 8_192).await?,
        )?);
    }

    for (index, expected_status) in [(0, StatusCode::OK), (1, StatusCode::CONFLICT)] {
        let response = router(Arc::clone(&state))
            .oneshot(json_mutation_request(
                "/api/v1/settings/protection/apply",
                &issued,
                Some(if index == 0 {
                    "protection-first"
                } else {
                    "protection-stale"
                }),
                serde_json::json!({
                    "settings": protection_settings(if index == 0 { 29 } else { 28 }),
                    "current_fingerprint": plans[index]["current_fingerprint"],
                    "plan_hash": plans[index]["plan_hash"]
                }),
            )?)
            .await?;
        assert_eq!(response.status(), expected_status);
        if index == 1 {
            let body = serde_json::from_slice::<serde_json::Value>(
                &to_bytes(response.into_body(), 8_192).await?,
            )?;
            assert_eq!(body["error"]["code"], "PROTECTION_PLAN_STALE");
        }
    }
    assert_eq!(
        state
            .protection
            .snapshot()?
            .settings
            .local_strict_requests_per_minute,
        29
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_action_is_not_applied_twice() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let issued = issue_session(&state)?;
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
    let issued = issue_session(&state)?;
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
    let issued = issue_session(&state)?;
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
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| event.kind == "provider.transaction_started")
    );
    assert!(
        events
            .iter()
            .any(|event| event.kind == "provider.action_failed")
    );
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
        ..TelemetryEnvelope::default()
    })?;

    let anonymous = router(Arc::clone(&state))
        .oneshot(
            Request::get("/api/v1/clients")
                .header("host", LOOPBACK_HOST)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let issued = issue_session(&state)?;
    let authenticated = router(Arc::clone(&state))
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

    let detail = router(Arc::clone(&state))
        .oneshot(
            Request::get("/api/v1/clients/203.0.113.8")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = to_bytes(detail.into_body(), 8_192).await?;
    let detail_json = serde_json::from_slice::<serde_json::Value>(&detail_body)?;
    assert_eq!(detail_json["client_ip"], "203.0.113.8");
    assert_eq!(detail_json["requests"], 1);
    assert_eq!(detail_json["max_route_cost"], 1);
    assert_eq!(detail_json["last_decision"], "allow");
    assert_eq!(detail_json["routes"][0]["normalized_route"], "/health");

    let invalid = router(state)
        .oneshot(
            Request::get("/api/v1/clients/not-an-ip")
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn authenticated_correlation_lookup_returns_request_detail()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let request_id = "guard-0123456789abcdef0123456789abcdef-0000000000000009";
    state.storage.record_traffic(&TelemetryEnvelope {
        schema_version: 1,
        request_id: request_id.to_owned(),
        method: "POST".to_owned(),
        route_class: "strict".to_owned(),
        normalized_route: "/api/login".to_owned(),
        route_cost: 5,
        status: 429,
        latency_micros: 1_500,
        client_ip: None,
        request_body_bytes: 64,
        response_body_bytes: 128,
        upstream_connection_reused: Some(true),
        decision: "throttle".to_owned(),
        policy_version: 3,
        occurred_at_unix_ms: 1_000,
        ..TelemetryEnvelope::default()
    })?;
    let issued = issue_session(&state)?;
    let response = router(state)
        .oneshot(
            Request::get(format!("/api/v1/correlations/{request_id}"))
                .header("host", LOOPBACK_HOST)
                .header("cookie", session_cookie(&issued))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16_384).await?;
    let value = serde_json::from_slice::<serde_json::Value>(&body)?;
    assert_eq!(value["request"]["request_id"], request_id);
    assert_eq!(value["request"]["method"], "POST");
    assert_eq!(value["request"]["status"], 429);
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
    let issued = issue_session(&state)?;
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
        ..TelemetryEnvelope::default()
    };
    state
        .traffic
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ingest(&telemetry);
    state.storage.record_traffic(&telemetry)?;
    let issued = issue_session(&state)?;

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

#[tokio::test]
async fn account_enrollment_totp_recovery_and_logout_work_through_api()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = app(&directory.path().join("state.json"))?;
    let bootstrap = state
        .bootstrap
        .issue(Duration::from_secs(300))
        .ok_or("bootstrap issue failed")?;

    let setup = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/auth/enrollment")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "login_code": bootstrap.code,
                        "username": "guard.admin",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(setup.status(), StatusCode::OK);
    let setup_body = to_bytes(setup.into_body(), 16_384).await?;
    let setup_json = serde_json::from_slice::<serde_json::Value>(&setup_body)?;
    let enrollment_id = setup_json["enrollment_id"]
        .as_str()
        .ok_or("enrollment id missing")?;
    let secret = setup_json["secret_base32"]
        .as_str()
        .ok_or("secret missing")?;
    let code = enrollment_totp(secret, "guard.admin")?;

    let confirmed = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/auth/enrollment/confirm")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "enrollment_id": enrollment_id,
                        "totp_code": code
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(confirmed.status(), StatusCode::OK);
    let cookie = confirmed
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .ok_or("session cookie missing")?
        .to_owned();
    let confirmed_body = to_bytes(confirmed.into_body(), 16_384).await?;
    let confirmed_json = serde_json::from_slice::<serde_json::Value>(&confirmed_body)?;
    assert_eq!(confirmed_json["session"]["actor"], "guard.admin");
    assert_eq!(
        confirmed_json["recovery_codes"].as_array().map(Vec::len),
        Some(10)
    );
    let csrf = confirmed_json["session"]["csrf_token"]
        .as_str()
        .ok_or("csrf missing")?;
    let recovery = confirmed_json["recovery_codes"][0]
        .as_str()
        .ok_or("recovery code missing")?
        .to_owned();

    let logout = router(Arc::clone(&state))
        .oneshot(
            Request::delete("/api/v1/session")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("cookie", cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(logout.status(), StatusCode::OK);
    assert!(
        logout
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("Max-Age=0"))
    );

    let recovery_body = serde_json::json!({
        "username": "guard.admin",
        "password": "correct horse battery staple",
        "recovery_code": recovery
    })
    .to_string();
    let recovery_login = router(Arc::clone(&state))
        .oneshot(
            Request::post("/api/v1/session")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(recovery_body.clone()))?,
        )
        .await?;
    assert_eq!(recovery_login.status(), StatusCode::OK);
    let recovery_json = serde_json::from_slice::<serde_json::Value>(
        &to_bytes(recovery_login.into_body(), 4_096).await?,
    )?;
    assert_eq!(recovery_json["authentication_method"], "password_recovery");

    let reused = router(state)
        .oneshot(
            Request::post("/api/v1/session")
                .header("host", LOOPBACK_HOST)
                .header("origin", LOOPBACK_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from(recovery_body))?,
        )
        .await?;
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);
    let reused_json =
        serde_json::from_slice::<serde_json::Value>(&to_bytes(reused.into_body(), 4_096).await?)?;
    assert_eq!(reused_json["error"]["code"], "ADMIN_AUTH_REJECTED");
    Ok(())
}
