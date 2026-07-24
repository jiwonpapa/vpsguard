//! loopback 관리 API와 embedded operations console을 제공합니다.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use guard_agent::os::OsSnapshot;
use guard_agent::{CollectorHealth, CollectorState};
use guard_core::config::{
    AdminAuthProvider, CspMode, DetectionMode, InspectionMode, SecurityConfig, TlsManagementMode,
};
use guard_core::correlation::{LOG_SCHEMA_VERSION, RequestIdGenerator, is_valid_request_id};
use guard_core::{GuardEvent, GuardMode, GuardState, Severity};
use guard_system::{
    AtomicJsonStore, CertbotPlanError, TlsManagementSnapshot, UfwError, UfwMutation,
    build_certbot_assisted_plan,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, RwLock, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tracing::Instrument;

use crate::auth::{
    AuthError, BootstrapStore, IssuedSession, LoginSecondFactor, SessionStore, UiAccessPolicy,
    unix_seconds,
};
use crate::firewall::{FirewallError, FirewallOperations};
use crate::notification::{NotificationHandle, NotificationStatus};
use crate::protection::{ProtectionPolicyError, ProtectionPolicyManager};
use crate::provider::ProviderController;
use crate::storage::{
    AuditActionRow, BotRow, ClientRow, EventRow, RequestTraceRow, RouteRow, SqliteStore,
    StorageHealthSnapshot,
};
use crate::telemetry::{TrafficAggregator, TrafficSummary};

macro_rules! api_warn {
    ($($field:tt)*) => {
        tracing::warn!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-control",
            $($field)*
        )
    };
}

mod protection_api;

const INDEX_HTML: &str = include_str!("../../../web/dist/index.html");
const APP_CSS: &str = include_str!("../../../web/dist/assets/app.css");
const APP_JS: &str = include_str!("../../../web/dist/assets/app.js");

/// control API 공유 상태입니다.
pub(crate) struct AppState {
    pub(crate) state: RwLock<GuardState>,
    pub(crate) state_store: AtomicJsonStore<GuardState>,
    pub(crate) traffic: Mutex<TrafficAggregator>,
    pub(crate) os_snapshot: RwLock<Option<OsSnapshot>>,
    pub(crate) service_health: RwLock<Vec<CollectorHealth>>,
    pub(crate) inspection_mode: InspectionMode,
    pub(crate) detection_mode: DetectionMode,
    pub(crate) security: SecurityConfig,
    pub(crate) waf: guard_core::config::WafConfig,
    pub(crate) tls_management: RwLock<TlsManagementSnapshot>,
    pub(crate) tls_plan_mode: TlsManagementMode,
    pub(crate) tls_plan_domains: Vec<String>,
    pub(crate) bootstrap: BootstrapStore,
    pub(crate) completed_actions: Mutex<VecDeque<(String, String, GuardMode)>>,
    pub(crate) storage: Arc<SqliteStore>,
    pub(crate) events: broadcast::Sender<GuardEvent>,
    pub(crate) notification: NotificationHandle,
    pub(crate) protection: Arc<ProtectionPolicyManager>,
    pub(crate) policy_operation: AsyncMutex<()>,
    pub(crate) sessions: Arc<SessionStore>,
    pub(crate) access: UiAccessPolicy,
    pub(crate) firewall: Arc<dyn FirewallOperations>,
    pub(crate) provider: Arc<Mutex<Option<ProviderController>>>,
    pub(crate) provider_action_active: Arc<AtomicBool>,
    pub(crate) request_ids: RequestIdGenerator,
}

/// overview 상태 응답입니다.
#[derive(Debug, Serialize)]
struct StatusResponse {
    schema_version: u32,
    inspection: InspectionMode,
    security: SecurityStatus,
    mode: GuardMode,
    manual_hold: bool,
    policy_version: u64,
    last_transition_at: String,
    reasons: Vec<&'static str>,
    edge: &'static str,
    origin: &'static str,
    agent: CollectorState,
    provider: String,
    provider_drain_deadline_unix_seconds: Option<u64>,
    tls: String,
    tls_management: TlsManagementSnapshot,
    notification: NotificationStatus,
}

#[derive(Debug, Serialize)]
struct SecurityStatus {
    app_layer_active: bool,
    baseline_response_headers: bool,
    strip_origin_headers: bool,
    csp_mode: CspMode,
    hsts_max_age_seconds: u64,
    auth_rate_limit_rpm: Option<u32>,
    waf_mode: guard_core::config::WafMode,
    waf_adapter: guard_core::config::WafAdapter,
}

/// resource endpoint 응답입니다.
#[derive(Debug, Serialize)]
struct ResourcesResponse {
    state: CollectorState,
    os: Option<OsSnapshot>,
    services: Vec<CollectorHealth>,
    storage: StorageHealthSnapshot,
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    applied: bool,
    mode: GuardMode,
    operation_id: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    problem: &'static str,
    cause: &'static str,
    impact: &'static str,
    next_action: &'static str,
    retriable: bool,
    event_id: String,
}

#[derive(Debug, Serialize)]
struct CorrelationResponse {
    correlation_id: String,
    request: Option<RequestTraceRow>,
    events: Vec<EventRow>,
    audit_action: Option<AuditActionRow>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SeriesQuery {
    since_unix_ms: Option<u64>,
    #[serde(default)]
    resolution: SeriesResolution,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
enum SeriesResolution {
    #[serde(rename = "1s")]
    OneSecond,
    #[serde(rename = "10s")]
    TenSeconds,
    #[default]
    #[serde(rename = "1m")]
    OneMinute,
}

#[derive(Debug, Serialize)]
struct ListResponse<T> {
    items: Vec<T>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    csrf_token: String,
    expires_in_seconds: u64,
    actor: String,
    authentication_method: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LoginRequest {
    Account(AccountLoginRequest),
    BreakGlass(BreakGlassLoginRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakGlassLoginRequest {
    login_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountLoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
    recovery_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentStartRequest {
    login_code: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentConfirmRequest {
    enrollment_id: String,
    totp_code: String,
}

#[derive(Debug, Serialize)]
struct AuthStatusResponse {
    auth_provider: AdminAuthProvider,
    setup_required: bool,
    enrollment_enabled: bool,
    password_login_enabled: bool,
    totp_required: bool,
    break_glass_available: bool,
}

#[derive(Debug, Serialize)]
struct EnrollmentStartResponse {
    enrollment_id: String,
    secret_base32: String,
    otpauth_uri: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
struct EnrollmentCompleteResponse {
    recovery_codes: Vec<String>,
    session: SessionResponse,
}

#[derive(Debug, Serialize)]
struct SessionMutationResponse {
    logged_out: bool,
    revoked_sessions: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsPlanRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FirewallApplyRequest {
    operation_id: String,
}

pub(crate) fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/traffic/summary", get(traffic_summary))
        .route("/api/v1/traffic/series", get(traffic_series))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/routes", get(routes))
        .route("/api/v1/bots", get(bots))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/correlations/{correlation_id}", get(correlation))
        .route("/api/v1/events", get(event_stream))
        .route("/api/v1/resources", get(resources))
        .route("/api/v1/firewall", get(firewall_status))
        .route("/api/v1/firewall/plan", post(firewall_plan))
        .route("/api/v1/firewall/apply", post(firewall_apply))
        .route("/api/v1/tls/assisted-plan", post(tls_assisted_plan))
        .route("/api/v1/settings/protection", get(protection_api::settings))
        .route(
            "/api/v1/settings/protection/plan",
            post(protection_api::plan),
        )
        .route(
            "/api/v1/settings/protection/apply",
            post(protection_api::apply),
        )
        .route("/api/v1/actions/manual-hold", post(manual_hold))
        .route("/api/v1/actions/resume-auto", post(resume_auto))
        .route("/api/v1/actions/emergency-proxy", post(emergency_proxy))
        .route("/api/v1/actions/provider-restore", post(provider_restore))
        .route("/api/v1/sessions/revoke-all", post(revoke_all_sessions))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_session,
        ));
    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(styles))
        .route("/assets/app.js", get(script))
        .route("/health/live", get(live))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/enrollment", post(start_enrollment))
        .route("/api/v1/auth/enrollment/confirm", post(confirm_enrollment))
        .route(
            "/api/v1/session",
            get(current_session)
                .post(create_session)
                .delete(delete_session),
        )
        .merge(protected)
        .fallback(index)
        .layer(DefaultBodyLimit::max(16 * 1_024))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            enforce_management_host,
        ))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            correlate_request,
        ))
        .with_state(state)
}

async fn correlate_request(
    State(app): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map_or_else(|| app.request_ids.next_id(), ToOwned::to_owned);
    let method = request.method().clone();
    let started_at = Instant::now();
    let span = tracing::info_span!(
        "control_request",
        log_schema_version = LOG_SCHEMA_VERSION,
        component = "guard-control",
        request_id = %request_id
    );
    let mut response = next.run(request).instrument(span.clone()).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    span.in_scope(|| {
        tracing::debug!(
            event_code = "CONTROL_REQUEST_COMPLETED",
            method = %method,
            status = response.status().as_u16(),
            latency_ms = started_at.elapsed().as_millis(),
            "control request completed"
        );
    });
    response
}

async fn enforce_management_host(
    State(app): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if path != "/health/live" {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok());
        if !app.access.accepts_host(host) {
            if path.starts_with("/api/") {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "MANAGEMENT_HOST_INVALID",
                    "관리 Host가 설정값과 일치하지 않습니다.",
                    "요청을 처리하거나 다른 origin으로 전달하지 않았습니다.",
                    "설정된 HTTPS 관리 주소로 다시 접속하십시오.",
                );
            }
            return (StatusCode::BAD_REQUEST, "invalid management host\n").into_response();
        }
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if path.starts_with("/api/") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn require_session(
    State(app): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let sessions = Arc::clone(&app.sessions);
    let headers = request.headers().clone();
    let authenticated = tokio::task::spawn_blocking(move || sessions.authenticate(&headers))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .is_some();
    if !authenticated {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_AUTH_REQUIRED",
            "유효한 운영 session이 필요합니다.",
            "관리 데이터와 운영 명령을 제공하지 않았습니다.",
            "관리자 계정과 2단계 인증으로 로그인하십시오.",
        );
    }
    next.run(request).await
}

async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            ),
        ],
        INDEX_HTML,
    )
}

async fn styles() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        APP_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        APP_JS,
    )
}

async fn live() -> &'static str {
    "live\n"
}

async fn status(State(app): State<Arc<AppState>>) -> Json<StatusResponse> {
    let state = app.state.read().await;
    let agent = if app.os_snapshot.read().await.is_some() {
        CollectorState::Live
    } else {
        CollectorState::Unavailable
    };
    let reasons = match state.current_mode {
        GuardMode::Normal => vec!["고정 안전 한도 안에서 관찰 중입니다."],
        GuardMode::ManualHold => vec!["관리자가 자동 상태 전이를 중지했습니다."],
        GuardMode::RecoveryReady => {
            vec!["서버가 안정됐지만 외부 보호 해제는 관리자 승인을 기다립니다."]
        }
        _ => vec!["최근 요청 비용과 자원 압력을 상세 관찰 중입니다."],
    };
    let (provider, provider_drain_deadline_unix_seconds) = match app.provider.try_lock() {
        Ok(guard) => guard.as_ref().map_or_else(
            || ("unavailable".to_owned(), None),
            |controller| {
                (
                    controller.status(),
                    controller.drain_deadline_unix_seconds(),
                )
            },
        ),
        Err(TryLockError::WouldBlock) => ("running".to_owned(), None),
        Err(TryLockError::Poisoned(error)) => error.into_inner().as_ref().map_or_else(
            || ("unavailable".to_owned(), None),
            |controller| {
                (
                    controller.status(),
                    controller.drain_deadline_unix_seconds(),
                )
            },
        ),
    };
    let tls_management = app.tls_management.read().await.clone();
    let app_layer_active = app.inspection_mode == InspectionMode::Profiled;
    let auth_rate_limit_rpm = (app_layer_active
        && app.detection_mode == DetectionMode::Enforce
        && app.security.auth_rate_limit_rpm > 0)
        .then_some(app.security.auth_rate_limit_rpm);
    Json(StatusResponse {
        schema_version: 1,
        inspection: app.inspection_mode,
        security: SecurityStatus {
            app_layer_active,
            baseline_response_headers: app.security.baseline_response_headers,
            strip_origin_headers: app.security.strip_origin_headers,
            csp_mode: if app_layer_active {
                app.security.csp_mode
            } else {
                CspMode::Off
            },
            hsts_max_age_seconds: app.security.hsts_max_age_seconds,
            auth_rate_limit_rpm,
            waf_mode: app.waf.mode,
            waf_adapter: app.waf.adapter,
        },
        mode: state.current_mode,
        manual_hold: state.manual_hold,
        policy_version: state.policy_version,
        last_transition_at: state.last_transition_at.clone(),
        reasons,
        edge: "live",
        origin: "unknown",
        agent,
        provider,
        provider_drain_deadline_unix_seconds,
        tls: tls_management.health.as_str().to_owned(),
        tls_management,
        notification: app.notification.status(),
    })
}

async fn traffic_summary(State(app): State<Arc<AppState>>) -> Json<TrafficSummary> {
    Json(lock_traffic(&app).summary_at(unix_millis()))
}

async fn resources(State(app): State<Arc<AppState>>) -> Json<ResourcesResponse> {
    let os = app.os_snapshot.read().await.clone();
    let services = app.service_health.read().await.clone();
    Json(ResourcesResponse {
        state: if os.is_some() {
            CollectorState::Live
        } else {
            CollectorState::Unavailable
        },
        os,
        services,
        storage: app.storage.health(),
    })
}

async fn firewall_status(State(app): State<Arc<AppState>>) -> Response {
    let firewall = Arc::clone(&app.firewall);
    match tokio::task::spawn_blocking(move || firewall.status()).await {
        Ok(Ok(status)) => Json(status).into_response(),
        Ok(Err(error)) => firewall_error_response(error),
        Err(error) => {
            api_warn!(
                error_code = "FIREWALL_STATUS_TASK_FAILED",
                error = %error,
                "firewall status task failed"
            );
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "FIREWALL_STATUS_TASK_FAILED",
                "방화벽 상태 작업이 종료됐습니다.",
                "방화벽 규칙을 변경하지 않았습니다.",
                "Control 로그와 UFW 상태를 확인하십시오.",
            )
        }
    }
}

async fn firewall_plan(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mutation): Json<UfwMutation>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    let firewall = Arc::clone(&app.firewall);
    match tokio::task::spawn_blocking(move || firewall.plan(mutation)).await {
        Ok(Ok(plan)) => Json(plan).into_response(),
        Ok(Err(error)) => firewall_error_response(error),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FIREWALL_PLAN_TASK_FAILED",
            "방화벽 plan 작업이 종료됐습니다.",
            "방화벽 규칙을 변경하지 않았습니다.",
            "Control 로그와 UFW 상태를 확인하십시오.",
        ),
    }
}

async fn firewall_apply(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<FirewallApplyRequest>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    if request.operation_id.trim().is_empty() || request.operation_id.len() > 64 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "FIREWALL_OPERATION_ID_INVALID",
            "방화벽 operation ID가 올바르지 않습니다.",
            "방화벽 규칙을 변경하지 않았습니다.",
            "plan 응답의 operation ID를 사용하십시오.",
        );
    }
    let firewall = Arc::clone(&app.firewall);
    match tokio::task::spawn_blocking(move || firewall.apply(&request.operation_id)).await {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(error)) => firewall_error_response(error),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FIREWALL_APPLY_TASK_FAILED",
            "방화벽 apply 작업이 종료됐습니다.",
            "적용 결과를 확정하지 못했습니다.",
            "UFW read-back과 SSH 연결을 확인하십시오.",
        ),
    }
}

fn firewall_error_response(error: FirewallError) -> Response {
    api_warn!(error_code = "FIREWALL_OPERATION_FAILED", error = %error);
    match error {
        FirewallError::Ufw(UfwError::OwnershipDenied) => api_error(
            StatusCode::CONFLICT,
            "FIREWALL_OWNERSHIP_DELEGATED",
            "VPSGuard가 host firewall 변경 소유자가 아닙니다.",
            "UFW와 nftables를 변경하지 않았습니다.",
            "JW-agent 또는 설치 topology의 firewall 소유자를 사용하십시오.",
        ),
        FirewallError::Ufw(UfwError::Inactive) => api_error(
            StatusCode::CONFLICT,
            "UFW_INACTIVE",
            "UFW가 비활성 상태입니다.",
            "VPSGuard가 UFW를 자동 활성화하지 않았습니다.",
            "SSH 허용 rule을 확인한 뒤 운영자가 UFW를 활성화하십시오.",
        ),
        FirewallError::Ufw(UfwError::SnapshotChanged) => api_error(
            StatusCode::CONFLICT,
            "UFW_SNAPSHOT_CHANGED",
            "승인 뒤 UFW 상태가 변경됐습니다.",
            "오래된 plan을 적용하지 않았습니다.",
            "새 snapshot으로 plan을 다시 생성하십시오.",
        ),
        FirewallError::PlanNotFound => api_error(
            StatusCode::NOT_FOUND,
            "FIREWALL_PLAN_NOT_FOUND",
            "승인 대기 중인 방화벽 plan이 없습니다.",
            "방화벽 규칙을 변경하지 않았습니다.",
            "새 plan을 생성해 검토한 뒤 적용하십시오.",
        ),
        FirewallError::Ufw(
            UfwError::InvalidRule(_) | UfwError::SshInvariant | UfwError::RuleIdentity(_),
        ) => api_error(
            StatusCode::BAD_REQUEST,
            "FIREWALL_RULE_REJECTED",
            "방화벽 규칙이 안전 계약을 위반했습니다.",
            "SSH와 기존 UFW 규칙을 보존했습니다.",
            "rule ID, source, port와 action을 확인하십시오.",
        ),
        FirewallError::Ufw(_) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "FIREWALL_OPERATION_FAILED",
            "방화벽 변경을 검증하지 못했습니다.",
            "검증 실패 시 VPSGuard 소유 변경을 원복했습니다.",
            "UFW read-back, audit와 SSH 연결을 확인하십시오.",
        ),
    }
}

async fn tls_assisted_plan(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<TlsPlanRequest>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    match build_certbot_assisted_plan(app.tls_plan_mode, &app.tls_plan_domains, &request.email) {
        Ok(plan) => Json(plan).into_response(),
        Err(CertbotPlanError::AssistedModeRequired) => api_error(
            StatusCode::CONFLICT,
            "TLS_ASSISTED_MODE_REQUIRED",
            "VPSGuard Certbot 보조 mode가 선택되지 않았습니다.",
            "인증서나 기존 갱신 설정을 변경하지 않았습니다.",
            "기존 관리자를 유지하거나 tls.management을 vpsguard_assisted로 명시하십시오.",
        ),
        Err(CertbotPlanError::InvalidDomain) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "TLS_HTTP01_DOMAIN_INVALID",
            "HTTP-01에 사용할 exact domain이 없습니다.",
            "발급 plan을 만들지 않았습니다.",
            "wildcard를 제외한 실제 서비스 hostname과 DNS를 확인하십시오.",
        ),
        Err(CertbotPlanError::InvalidEmail) => api_error(
            StatusCode::BAD_REQUEST,
            "TLS_ACME_EMAIL_INVALID",
            "ACME 연락처 email 형식이 잘못됐습니다.",
            "발급 plan을 만들지 않았습니다.",
            "공백 없는 실제 연락처 email을 입력하십시오.",
        ),
    }
}

async fn edge_observed_policy_version(app: &AppState) -> Result<Option<u64>, Response> {
    let storage = Arc::clone(&app.storage);
    match tokio::task::spawn_blocking(move || storage.latest_policy_version()).await {
        Ok(Ok(version)) => Ok(version),
        Ok(Err(error)) => {
            api_warn!(
                error_code = "EDGE_POLICY_READBACK_UNAVAILABLE",
                error = %error,
                "edge policy telemetry read-back failed"
            );
            Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "EDGE_POLICY_READBACK_UNAVAILABLE",
                "Edge가 관측한 policy version을 읽지 못했습니다.",
                "설정 파일 적용 여부와 Edge 실제 반영 여부를 구분할 수 없습니다.",
                "Control 저장 계층과 telemetry 수집 상태를 확인하십시오.",
            ))
        }
        Err(error) => {
            api_warn!(
                error_code = "EDGE_POLICY_READBACK_TASK_FAILED",
                error = %error,
                "edge policy telemetry read-back task failed"
            );
            Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EDGE_POLICY_READBACK_TASK_FAILED",
                "Edge policy read-back task가 종료됐습니다.",
                "설정 파일 적용 여부와 Edge 실제 반영 여부를 구분할 수 없습니다.",
                "Control 로그와 runtime worker 상태를 확인하십시오.",
            ))
        }
    }
}

fn protection_policy_error(error: ProtectionPolicyError) -> Response {
    match error {
        ProtectionPolicyError::InvalidSettings(_) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PROTECTION_SETTINGS_INVALID",
            "보호 제한값이 안전 계약을 위반했습니다.",
            "현재 policy와 Edge 동작을 변경하지 않았습니다.",
            "각 값을 1..=6000 범위로 두고 WATCH ≥ LOCAL ≥ EMERGENCY, strict ≥ upload 관계를 확인하십시오.",
        ),
        ProtectionPolicyError::StalePlan => api_error(
            StatusCode::CONFLICT,
            "PROTECTION_PLAN_STALE",
            "계획을 만든 뒤 보호 설정이 변경됐습니다.",
            "오래된 후보를 적용하지 않았습니다.",
            "현재 설정을 다시 읽고 diff 계획을 새로 만드십시오.",
        ),
        ProtectionPolicyError::PlanHashMismatch => api_error(
            StatusCode::BAD_REQUEST,
            "PROTECTION_PLAN_HASH_MISMATCH",
            "보호 설정 plan hash가 후보와 일치하지 않습니다.",
            "현재 policy를 변경하지 않았습니다.",
            "후보를 수정했다면 plan을 다시 생성하십시오.",
        ),
        ProtectionPolicyError::IdempotencyConflict => idempotency_conflict(),
        ProtectionPolicyError::VersionExhausted => api_error(
            StatusCode::CONFLICT,
            "PROTECTION_POLICY_VERSION_EXHAUSTED",
            "보호 policy version을 더 증가시킬 수 없습니다.",
            "현재 마지막 정상 policy를 유지합니다.",
            "상태 파일과 policy version을 운영자가 점검하십시오.",
        ),
        ProtectionPolicyError::Policy(_)
        | ProtectionPolicyError::Store(_)
        | ProtectionPolicyError::Serialize(_)
        | ProtectionPolicyError::Time(_)
        | ProtectionPolicyError::ReadBackMismatch
        | ProtectionPolicyError::UnsupportedMetadataSchema(_)
        | ProtectionPolicyError::MetadataHashMismatch
        | ProtectionPolicyError::MetadataVersionBehind { .. }
        | ProtectionPolicyError::PolicySettingsMismatch
        | ProtectionPolicyError::MissingPolicy(_)
        | ProtectionPolicyError::StateVersionAhead { .. } => {
            api_warn!(
                error_code = "PROTECTION_POLICY_APPLY_FAILED",
                error = %error,
                "protection policy apply failed"
            );
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PROTECTION_POLICY_APPLY_FAILED",
                "보호 policy를 원자 적용·검증하지 못했습니다.",
                "Control이 적용 성공을 확정하지 않으며 Edge는 검증 가능한 policy만 사용합니다.",
                "policy 경로 권한, disk 여유와 Control 로그를 확인하십시오.",
            )
        }
    }
}

async fn traffic_series(
    State(app): State<Arc<AppState>>,
    Query(query): Query<SeriesQuery>,
) -> Response {
    let since = query.since_unix_ms.unwrap_or_else(|| {
        unix_millis().saturating_sub(24_u64.saturating_mul(60).saturating_mul(60_000))
    });
    match query.resolution {
        SeriesResolution::OneSecond => Json(ListResponse {
            items: lock_traffic(&app).live_series(since),
        })
        .into_response(),
        SeriesResolution::TenSeconds => storage_list(app.storage.ten_second_series(since)),
        SeriesResolution::OneMinute => storage_list(app.storage.series(since)),
    }
}

async fn clients(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    let result = app.storage.clients(bounded_limit(query.limit));
    storage_list::<ClientRow>(result)
}

async fn routes(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    storage_list::<RouteRow>(app.storage.routes(bounded_limit(query.limit)))
}

async fn bots(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    storage_list::<BotRow>(app.storage.bots(bounded_limit(query.limit)))
}

async fn incidents(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    storage_list::<EventRow>(app.storage.events(bounded_limit(query.limit)))
}

async fn correlation(
    State(app): State<Arc<AppState>>,
    Path(correlation_id): Path<String>,
) -> Response {
    if !valid_correlation_id(&correlation_id) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "CORRELATION_ID_INVALID",
            "상관관계 식별자 형식이 올바르지 않습니다.",
            "저장된 요청·사건·감사 기록을 조회하지 않았습니다.",
            "응답의 X-Request-ID, 운영 operation ID 또는 사건 event ID를 입력하십시오.",
        );
    }
    let request = match app.storage.request_trace(&correlation_id) {
        Ok(request) => request,
        Err(error) => return correlation_storage_error(&error),
    };
    let events = match app.storage.events_for_correlation(&correlation_id, 32) {
        Ok(events) => events,
        Err(error) => return correlation_storage_error(&error),
    };
    let audit_action = match app.storage.audit_action(&correlation_id) {
        Ok(action) => action,
        Err(error) => return correlation_storage_error(&error),
    };
    if request.is_none() && events.is_empty() && audit_action.is_none() {
        return api_error(
            StatusCode::NOT_FOUND,
            "CORRELATION_NOT_FOUND",
            "보존 중인 상관관계 기록을 찾지 못했습니다.",
            "현재 운영 상태와 저장된 기록은 변경하지 않았습니다.",
            "식별자를 확인하고 detail·incident·audit 보존기간 안의 기록인지 확인하십시오.",
        );
    }
    Json(CorrelationResponse {
        correlation_id,
        request,
        events,
        audit_action,
    })
    .into_response()
}

fn correlation_storage_error(error: &crate::storage::StorageError) -> Response {
    tracing::warn!(
        log_schema_version = LOG_SCHEMA_VERSION,
        component = "guard-control",
        error_code = "CORRELATION_STORAGE_QUERY_FAILED",
        error = %error,
        "correlation query failed"
    );
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "CORRELATION_STORAGE_QUERY_FAILED",
        "상관관계 저장소를 조회하지 못했습니다.",
        "방어 동작은 계속되지만 요청 추적 결과를 제공하지 못했습니다.",
        "SQLite 상태와 disk 여유를 확인한 뒤 다시 시도하십시오.",
    )
}

async fn event_stream(
    State(app): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(app.events.subscribe()).filter_map(|result| {
        let event = result.ok()?;
        Event::default()
            .id(event.event_id.clone())
            .event(event.kind.clone())
            .json_data(event)
            .ok()
            .map(Ok)
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}

async fn current_session(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let sessions = Arc::clone(&app.sessions);
    let result = tokio::task::spawn_blocking(move || sessions.resume(&headers)).await;
    let Ok(Ok(Some((csrf_token, identity)))) = result else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_AUTH_REQUIRED",
            "유효한 운영 session이 없습니다.",
            "CSRF token을 복원하지 않았습니다.",
            "관리자 계정과 2단계 인증으로 로그인하십시오.",
        );
    };
    Json(SessionResponse {
        csrf_token,
        expires_in_seconds: identity.expires_in_seconds,
        actor: identity.actor,
        authentication_method: identity.authentication_method,
    })
    .into_response()
}

async fn auth_status(State(app): State<Arc<AppState>>) -> Response {
    let auth_provider = app.sessions.auth_provider();
    let enrollment_enabled = app.sessions.enrollment_enabled();
    let sessions = Arc::clone(&app.sessions);
    match tokio::task::spawn_blocking(move || sessions.setup_required()).await {
        Ok(Ok(setup_required)) => Json(AuthStatusResponse {
            auth_provider,
            setup_required,
            enrollment_enabled,
            password_login_enabled: !setup_required,
            totp_required: !setup_required,
            break_glass_available: true,
        })
        .into_response(),
        _ => auth_error_response(AuthError::Crypto),
    }
}

async fn start_enrollment(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<EnrollmentStartRequest>,
) -> Response {
    if let Some(error) = invalid_origin_error(&headers, &app) {
        return error;
    }
    if let Err(error) = app.sessions.allow_login_attempt() {
        return auth_error_response(error);
    }
    if let Err(error) = app
        .sessions
        .validate_new_credentials(&request.username, &request.password)
    {
        return auth_error_response(error);
    }
    let sessions = Arc::clone(&app.sessions);
    match tokio::task::spawn_blocking(move || sessions.setup_required()).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return auth_error_response(AuthError::AlreadyConfigured),
        Ok(Err(error)) => return auth_error_response(error),
        Err(_) => return auth_error_response(AuthError::Crypto),
    }
    if !valid_bootstrap_code(&request.login_code) || !app.bootstrap.consume(&request.login_code) {
        return login_code_error();
    }
    let sessions = Arc::clone(&app.sessions);
    let username = request.username;
    let password = SecretString::from(request.password);
    match tokio::task::spawn_blocking(move || {
        sessions.start_enrollment(username, password, unix_seconds()?)
    })
    .await
    {
        Ok(Ok(enrollment)) => Json(EnrollmentStartResponse {
            enrollment_id: enrollment.enrollment_id,
            secret_base32: enrollment.secret_base32,
            otpauth_uri: enrollment.otpauth_uri,
            expires_in_seconds: enrollment.expires_in_seconds,
        })
        .into_response(),
        Ok(Err(error)) => auth_error_response(error),
        Err(_) => auth_error_response(AuthError::Crypto),
    }
}

async fn confirm_enrollment(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<EnrollmentConfirmRequest>,
) -> Response {
    if let Some(error) = invalid_origin_error(&headers, &app) {
        return error;
    }
    if let Err(error) = app.sessions.allow_login_attempt() {
        return auth_error_response(error);
    }
    let sessions = Arc::clone(&app.sessions);
    let secure_cookie = app.access.secure_cookie();
    let result = tokio::task::spawn_blocking(move || {
        sessions.confirm_enrollment(
            &request.enrollment_id,
            &request.totp_code,
            secure_cookie,
            unix_seconds()?,
        )
    })
    .await;
    match result {
        Ok(Ok(complete)) => {
            let cookie = complete.session.set_cookie.clone();
            (
                [(header::SET_COOKIE, cookie)],
                Json(EnrollmentCompleteResponse {
                    recovery_codes: complete.recovery_codes,
                    session: session_response(complete.session),
                }),
            )
                .into_response()
        }
        Ok(Err(error)) => auth_error_response(error),
        Err(_) => auth_error_response(AuthError::Crypto),
    }
}

async fn create_session(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if let Some(error) = invalid_origin_error(&headers, &app) {
        return error;
    }
    if let Err(error) = app.sessions.allow_login_attempt() {
        return auth_error_response(error);
    }
    let sessions = Arc::clone(&app.sessions);
    let secure_cookie = app.access.secure_cookie();
    let result = match request {
        LoginRequest::Account(request) => {
            let second_factor = match (request.totp_code, request.recovery_code) {
                (Some(code), None) => LoginSecondFactor::Totp(code),
                (None, Some(code)) => LoginSecondFactor::RecoveryCode(code),
                _ => return invalid_login_error(),
            };
            tokio::task::spawn_blocking(move || {
                sessions.login(
                    request.username,
                    SecretString::from(request.password),
                    second_factor,
                    secure_cookie,
                    unix_seconds()?,
                )
            })
            .await
        }
        LoginRequest::BreakGlass(request) => {
            if !valid_bootstrap_code(&request.login_code)
                || !app.bootstrap.consume(&request.login_code)
            {
                return login_code_error();
            }
            tokio::task::spawn_blocking(move || {
                sessions.issue_break_glass(secure_cookie, unix_seconds()?)
            })
            .await
        }
    };
    match result {
        Ok(Ok(issued)) => {
            let cookie = issued.set_cookie.clone();
            (
                [(header::SET_COOKIE, cookie)],
                Json(session_response(issued)),
            )
                .into_response()
        }
        Ok(Err(AuthError::RateLimited)) => auth_error_response(AuthError::RateLimited),
        Ok(Err(_)) => invalid_login_error(),
        Err(_) => auth_error_response(AuthError::Crypto),
    }
}

async fn delete_session(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    let sessions = Arc::clone(&app.sessions);
    let secure_cookie = app.access.secure_cookie();
    match tokio::task::spawn_blocking(move || sessions.logout(&headers, secure_cookie)).await {
        Ok(Ok(Some(cookie))) => (
            [(header::SET_COOKIE, cookie)],
            Json(SessionMutationResponse {
                logged_out: true,
                revoked_sessions: 1,
            }),
        )
            .into_response(),
        Ok(Ok(None)) => invalid_login_error(),
        _ => auth_error_response(AuthError::Crypto),
    }
}

async fn revoke_all_sessions(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    let sessions = Arc::clone(&app.sessions);
    let auth_headers = headers.clone();
    let secure_cookie = app.access.secure_cookie();
    match tokio::task::spawn_blocking(move || sessions.revoke_all(&auth_headers)).await {
        Ok(Ok(Some(count))) => (
            [(header::SET_COOKIE, expired_session_cookie(secure_cookie))],
            Json(SessionMutationResponse {
                logged_out: true,
                revoked_sessions: count,
            }),
        )
            .into_response(),
        Ok(Ok(None)) => invalid_login_error(),
        _ => auth_error_response(AuthError::Crypto),
    }
}

async fn manual_hold(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_action(&app, &headers, true).await
}

async fn resume_auto(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_action(&app, &headers, false).await
}

async fn emergency_proxy(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_provider_action(&app, &headers, false).await
}

async fn provider_restore(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_provider_action(&app, &headers, true).await
}

async fn apply_provider_action(
    app: &Arc<AppState>,
    headers: &HeaderMap,
    restore: bool,
) -> Response {
    if let Some(error) = mutation_authorization_error(headers, app).await {
        return error;
    }
    let Some(operation_id) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key가 필요합니다.",
            "Provider 상태를 변경하지 않았습니다.",
            "고유 operation ID로 다시 요청하십시오.",
        );
    };
    let action_name = if restore {
        "provider_restore"
    } else {
        "emergency_proxy"
    };
    if let Some((completed_action, mode)) = completed_action(app, &operation_id) {
        if completed_action != action_name {
            return idempotency_conflict();
        }
        return Json(ActionResponse {
            applied: false,
            mode,
            operation_id,
        })
        .into_response();
    }
    if app.state.read().await.manual_hold {
        return api_error(
            StatusCode::CONFLICT,
            "MANUAL_HOLD_ACTIVE",
            "수동 고정 중에는 provider 전환을 실행하지 않습니다.",
            "Cloudflare와 원본 firewall 상태를 변경하지 않았습니다.",
            "자동 대응을 재개한 뒤 다시 검토하십시오.",
        );
    }
    let Some(_provider_action_lease) = ProviderActionLease::acquire(app) else {
        return api_error(
            StatusCode::CONFLICT,
            "PROVIDER_ACTION_IN_PROGRESS",
            "다른 provider transaction이 실행 중입니다.",
            "충돌하는 운영 명령을 적용하지 않았습니다.",
            "현재 단계가 완료된 뒤 다시 시도하십시오.",
        );
    };
    record_provider_started(app, &operation_id, action_name);
    let provider = Arc::clone(&app.provider);
    let operation_for_task = operation_id.clone();
    let provider_result = tokio::task::spawn_blocking(move || {
        let mut guard = provider
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let controller = guard
            .as_mut()
            .ok_or_else(|| "PROVIDER_NOT_CONFIGURED".to_owned())?;
        if restore {
            controller
                .restore()
                .map_err(|error| error.code().to_owned())
        } else {
            controller
                .enable(&operation_for_task)
                .map_err(|error| error.code().to_owned())
        }
    })
    .await;
    let stage = match provider_result {
        Ok(Ok(stage)) => stage,
        Ok(Err(error)) => {
            api_warn!(
                error_code = "PROVIDER_ACTION_FAILED",
                error,
                operation_id,
                "provider action failed"
            );
            record_provider_failure(app, &operation_id, action_name, &error);
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "PROVIDER_ACTION_FAILED",
                "Provider transaction을 완료하지 못했습니다.",
                "저장된 단계에서 재개하거나 snapshot 복구가 필요합니다.",
                "Provider 상태와 사건 timeline을 확인한 뒤 같은 operation ID로 재시도하십시오.",
            );
        }
        Err(error) => {
            api_warn!(
                error_code = "PROVIDER_TASK_FAILED",
                error = %error,
                operation_id,
                "provider task failed"
            );
            record_provider_failure(app, &operation_id, action_name, "PROVIDER_TASK_JOIN_FAILED");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PROVIDER_TASK_FAILED",
                "Provider 작업 task가 종료됐습니다.",
                "Edge와 로컬 보호는 계속 동작합니다.",
                "Control 로그를 확인하십시오.",
            );
        }
    };
    let now = current_timestamp();
    let mut next = app.state.read().await.clone();
    next.current_mode = if restore {
        GuardMode::Recovering
    } else {
        GuardMode::EmergencyProxy
    };
    if restore {
        next.breach_windows = 0;
        next.stable_windows = 0;
    }
    next.last_transition_at.clone_from(&now);
    if !restore && next.active_incident_id.is_none() {
        next.active_incident_id = Some(format!("provider-{operation_id}"));
    }
    let store = app.state_store.clone();
    let value = next.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || store.write(&value)).await,
        Ok(Ok(()))
    ) {
        record_provider_failure(app, &operation_id, action_name, "STATE_WRITE_FAILED");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STATE_WRITE_FAILED",
            "Provider 결과 뒤 제어 상태를 저장하지 못했습니다.",
            "Provider transaction state는 별도 저장됐지만 UI 상태가 지연됩니다.",
            "disk 상태를 확인하고 저장된 provider transaction을 read-back하십시오.",
        );
    }
    *app.state.write().await = next.clone();
    remember_action(app, operation_id.clone(), action_name, next.current_mode);
    if let Err(error) = app.storage.record_action(
        &operation_id,
        &now,
        action_name,
        mode_name(next.current_mode),
        &format!("{:?}", stage),
    ) {
        api_warn!(
            error_code = "PROVIDER_AUDIT_PERSISTENCE_FAILED",
            error = %error,
            operation_id,
            "provider audit persistence failed"
        );
    }
    let event = provider_event(
        operation_id.clone(),
        now,
        action_name,
        next.current_mode,
        stage,
    );
    publish_event(app, event);
    Json(ActionResponse {
        applied: true,
        mode: next.current_mode,
        operation_id,
    })
    .into_response()
}

async fn apply_action(app: &Arc<AppState>, headers: &HeaderMap, hold: bool) -> Response {
    if let Some(error) = mutation_authorization_error(headers, app).await {
        return error;
    }
    let Some(operation_id) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key가 필요합니다.",
            "방어 상태를 변경하지 않았습니다.",
            "고유 operation ID로 다시 요청하십시오.",
        );
    };
    let action_name = if hold { "manual_hold" } else { "resume_auto" };
    if let Some((completed_action, mode)) = completed_action(app, &operation_id) {
        if completed_action != action_name {
            return idempotency_conflict();
        }
        return Json(ActionResponse {
            applied: false,
            mode,
            operation_id,
        })
        .into_response();
    }
    let now = current_timestamp();
    let next = {
        let state = app.state.read().await.clone();
        if hold {
            state.hold(now.clone())
        } else {
            state.resume(now.clone())
        }
    };
    let store = app.state_store.clone();
    let write_value = next.clone();
    let write_result = tokio::task::spawn_blocking(move || store.write(&write_value)).await;
    if !matches!(write_result, Ok(Ok(()))) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "STATE_WRITE_FAILED",
            "제어 상태를 원자 저장하지 못했습니다.",
            "메모리 상태도 변경하지 않았습니다.",
            "state directory 권한과 disk 여유 공간을 확인하십시오.",
        );
    }
    *app.state.write().await = next.clone();
    remember_action(app, operation_id.clone(), action_name, next.current_mode);
    if let Err(error) = app.storage.record_action(
        &operation_id,
        &now,
        action_name,
        mode_name(next.current_mode),
        "applied",
    ) {
        api_warn!(
            error_code = "ACTION_AUDIT_PERSISTENCE_FAILED",
            error = %error,
            operation_id,
            "action audit persistence failed"
        );
    }
    let event = action_event(operation_id.clone(), now, action_name, next.current_mode);
    publish_event(app, event);
    Json(ActionResponse {
        applied: true,
        mode: next.current_mode,
        operation_id,
    })
    .into_response()
}

async fn mutation_authorization_error(headers: &HeaderMap, app: &AppState) -> Option<Response> {
    if !app.access.accepts_origin(headers) {
        return Some(api_error(
            StatusCode::FORBIDDEN,
            "MANAGEMENT_ORIGIN_INVALID",
            "요청 Origin이 관리 주소와 일치하지 않습니다.",
            "운영 상태를 변경하지 않았습니다.",
            "설정된 HTTPS 관리 주소에서 다시 시도하십시오.",
        ));
    }
    let sessions = Arc::clone(&app.sessions);
    let headers = headers.clone();
    let authorized = tokio::task::spawn_blocking(move || sessions.authorize(&headers))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .is_some();
    if !authorized {
        return Some(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_AUTH_REQUIRED",
            "session에 연결된 CSRF token이 필요합니다.",
            "운영 상태를 변경하지 않았습니다.",
            "session을 복원한 뒤 명령을 다시 확인하십시오.",
        ));
    }
    None
}

fn invalid_origin_error(headers: &HeaderMap, app: &AppState) -> Option<Response> {
    (!app.access.accepts_origin(headers)).then(|| {
        api_error(
            StatusCode::FORBIDDEN,
            "MANAGEMENT_ORIGIN_INVALID",
            "요청 Origin이 관리 주소와 일치하지 않습니다.",
            "인증 상태를 변경하지 않았습니다.",
            "설정된 HTTPS 관리 주소에서 다시 시도하십시오.",
        )
    })
}

fn session_response(issued: IssuedSession) -> SessionResponse {
    SessionResponse {
        csrf_token: issued.csrf_token,
        expires_in_seconds: issued.expires_in_seconds,
        actor: issued.actor,
        authentication_method: issued.authentication_method.as_str().to_owned(),
    }
}

fn valid_bootstrap_code(code: &str) -> bool {
    code.len() == 64 && code.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn login_code_error() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "LOGIN_CODE_REJECTED",
        "단회 설정·복구 code가 유효하지 않습니다.",
        "관리자 등록 또는 break-glass session을 생성하지 않았습니다.",
        "서버에서 새 단회 code를 발급한 뒤 만료 전에 다시 시도하십시오.",
    )
}

fn invalid_login_error() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        "ADMIN_AUTH_REJECTED",
        "관리자 인증 정보가 올바르지 않습니다.",
        "운영 session을 생성하지 않았습니다.",
        "관리자 ID, 비밀번호와 2단계 인증값을 확인하십시오.",
    )
}

fn auth_error_response(error: AuthError) -> Response {
    match error {
        AuthError::InvalidUsername => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ADMIN_USERNAME_INVALID",
            "관리자 ID 형식이 올바르지 않습니다.",
            "관리자 등록을 진행하지 않았습니다.",
            "영문·숫자로 시작하는 3~32자의 영문·숫자·점·밑줄·하이픈을 사용하십시오.",
        ),
        AuthError::WeakPassword => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "ADMIN_PASSWORD_WEAK",
            "비밀번호 길이 정책을 충족하지 못했습니다.",
            "관리자 등록을 진행하지 않았습니다.",
            "12자 이상 1,024 byte 이하의 비밀번호를 사용하십시오.",
        ),
        AuthError::AlreadyConfigured => api_error(
            StatusCode::CONFLICT,
            "ADMIN_ALREADY_CONFIGURED",
            "최초 관리자 계정이 이미 등록됐습니다.",
            "기존 계정과 TOTP 설정을 변경하지 않았습니다.",
            "기존 관리자 계정으로 로그인하거나 서버에서 break-glass code를 발급하십시오.",
        ),
        AuthError::EnrollmentUnavailable => api_error(
            StatusCode::GONE,
            "ADMIN_ENROLLMENT_UNAVAILABLE",
            "관리자 등록 session이 없거나 만료됐습니다.",
            "관리자 계정과 TOTP를 저장하지 않았습니다.",
            "새 단회 설정 code로 등록을 다시 시작하십시오.",
        ),
        AuthError::EnrollmentDisabled => api_error(
            StatusCode::CONFLICT,
            "ADMIN_ENROLLMENT_DISABLED",
            "선택한 관리자 인증 provider는 최초 등록을 지원하지 않습니다.",
            "관리자 credential을 변경하지 않았습니다.",
            "인증 provider 설정과 privileged helper 상태를 확인하십시오.",
        ),
        AuthError::InvalidTotp => api_error(
            StatusCode::UNAUTHORIZED,
            "ADMIN_TOTP_REJECTED",
            "2단계 인증 code가 올바르지 않습니다.",
            "관리자 등록을 완료하지 않았습니다.",
            "인증기 시간과 6자리 code를 확인하십시오.",
        ),
        AuthError::RateLimited => {
            let mut response = api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ADMIN_LOGIN_RATE_LIMITED",
                "관리자 인증 시도 한도를 초과했습니다.",
                "추가 인증 시도를 잠시 받지 않습니다.",
                "60초 후 다시 시도하십시오.",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            response
        }
        AuthError::InvalidCredentials | AuthError::Pam => invalid_login_error(),
        AuthError::Store(_) | AuthError::Crypto | AuthError::Clock => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ADMIN_AUTH_UNAVAILABLE",
            "관리자 인증 service가 요청을 완료하지 못했습니다.",
            "인증 정보와 운영 상태를 변경하지 않았습니다.",
            "VPSGuard control 로그와 인증 database 상태를 확인하십시오.",
        ),
    }
}

fn expired_session_cookie(secure: bool) -> String {
    let name = if secure {
        "__Host-vps_guard_session"
    } else {
        "vps_guard_session"
    };
    let secure_attribute = if secure { "; Secure" } else { "" };
    format!("{name}=; Path=/; HttpOnly; SameSite=Strict{secure_attribute}; Max-Age=0")
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    problem: &'static str,
    impact: &'static str,
    next_action: &'static str,
) -> Response {
    let cause = api_error_cause(code);
    let event_id = format!("error-{}", uuid::Uuid::new_v4().simple());
    if status.is_server_error() {
        tracing::warn!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-control",
            error_code = code,
            event_id = %event_id,
            problem,
            cause,
            impact,
            next_action,
            "control API error"
        );
    } else {
        tracing::info!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-control",
            event_code = "CONTROL_API_REQUEST_REJECTED",
            error_code = code,
            event_id = %event_id,
            problem,
            cause,
            impact,
            next_action,
            "control API request rejected"
        );
    }
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail {
                code,
                problem,
                cause,
                impact,
                next_action,
                retriable: true,
                event_id,
            },
        }),
    )
        .into_response()
}

fn api_error_cause(code: &str) -> &'static str {
    match code {
        "MANAGEMENT_HOST_INVALID" => "Host header가 설정된 관리 hostname과 일치하지 않습니다.",
        "MANAGEMENT_ORIGIN_INVALID" => {
            "Origin header가 설정된 HTTPS 관리 origin과 일치하지 않습니다."
        }
        "SESSION_AUTH_REQUIRED" => "유효하고 만료되지 않은 관리자 session을 확인하지 못했습니다.",
        "CSRF_AUTH_REQUIRED" => "session에 연결된 CSRF token 검증을 통과하지 못했습니다.",
        "TLS_ASSISTED_MODE_REQUIRED" => {
            "현재 TLS 소유권 mode가 VPSGuard 보조 발급을 허용하지 않습니다."
        }
        "TLS_HTTP01_DOMAIN_INVALID" => "HTTP-01에 사용할 exact non-wildcard domain이 없습니다.",
        "TLS_ACME_EMAIL_INVALID" => "ACME 연락처가 bounded email 형식 검증을 통과하지 못했습니다.",
        "IDEMPOTENCY_KEY_REQUIRED" => "요청 header에 비어 있지 않은 Idempotency-Key가 없습니다.",
        "IDEMPOTENCY_KEY_CONFLICT" => {
            "기존 operation ID에 기록된 명령과 현재 명령이 서로 다릅니다."
        }
        "MANUAL_HOLD_ACTIVE" => "현재 방어 상태가 관리자 수동 고정 상태입니다.",
        "PROVIDER_ACTION_IN_PROGRESS" => "다른 provider transaction lease가 이미 활성 상태입니다.",
        "PROVIDER_ACTION_FAILED" => "provider transaction 단계가 오류를 반환했습니다.",
        "PROVIDER_TASK_FAILED" => "blocking provider task가 정상 결과 없이 종료됐습니다.",
        "STATE_WRITE_FAILED" => "원자 state 저장 또는 read-back을 완료하지 못했습니다.",
        "LOGIN_CODE_REJECTED" => "단회 code가 형식·만료·재사용 검증 중 하나를 통과하지 못했습니다.",
        "ADMIN_AUTH_REJECTED" => "관리자 credential과 2단계 인증 조합을 확인하지 못했습니다.",
        "ADMIN_USERNAME_INVALID" => "관리자 ID가 길이 또는 허용 문자 규칙을 위반했습니다.",
        "ADMIN_PASSWORD_WEAK" => "관리자 비밀번호가 최소 길이 또는 최대 byte 규칙을 위반했습니다.",
        "ADMIN_ALREADY_CONFIGURED" => "관리자 계정 저장소에 이미 활성 계정이 있습니다.",
        "ADMIN_ENROLLMENT_UNAVAILABLE" => "등록 session이 없거나 유효기간을 지났습니다.",
        "ADMIN_TOTP_REJECTED" => "제출한 TOTP가 허용 시간창의 값과 일치하지 않습니다.",
        "ADMIN_LOGIN_RATE_LIMITED" => "bounded 로그인 시도 한도가 현재 시간창에서 소진됐습니다.",
        "ADMIN_AUTH_UNAVAILABLE" => "인증 저장소·암호 처리·시각 중 하나를 사용할 수 없습니다.",
        "STORAGE_QUERY_FAILED" | "CORRELATION_STORAGE_QUERY_FAILED" => {
            "Control SQLite 조회가 정상 결과를 반환하지 못했습니다."
        }
        "CORRELATION_ID_INVALID" => "식별자가 허용 길이 또는 문자 규칙을 위반했습니다.",
        "CORRELATION_NOT_FOUND" => "현재 detail·incident·audit 보존 계층에 일치값이 없습니다.",
        _ => "요청 처리 전제조건 또는 내부 작업이 안정적 오류 code와 함께 실패했습니다.",
    }
}

fn lock_traffic(app: &AppState) -> MutexGuard<'_, TrafficAggregator> {
    app.traffic
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn completed_action(app: &AppState, operation_id: &str) -> Option<(String, GuardMode)> {
    let memory_mode = app
        .completed_actions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find_map(|(completed_id, action, mode)| {
            (completed_id == operation_id).then(|| (action.clone(), *mode))
        });
    memory_mode.or_else(|| {
        app.storage
            .completed_action(operation_id)
            .ok()
            .flatten()
            .and_then(|(action, mode)| parse_mode(&mode).map(|parsed| (action, parsed)))
    })
}

fn remember_action(app: &AppState, operation_id: String, action: &str, mode: GuardMode) {
    const MAX_COMPLETED_ACTIONS: usize = 1_024;
    let mut actions = app
        .completed_actions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if actions.len() == MAX_COMPLETED_ACTIONS {
        actions.pop_front();
    }
    actions.push_back((operation_id, action.to_owned(), mode));
}

fn idempotency_conflict() -> Response {
    api_error(
        StatusCode::CONFLICT,
        "IDEMPOTENCY_KEY_CONFLICT",
        "같은 Idempotency-Key가 다른 운영 명령에 사용됐습니다.",
        "새 운영 명령을 적용하지 않았습니다.",
        "명령마다 고유 operation ID를 사용하십시오.",
    )
}

pub(crate) struct ProviderActionLease {
    active: Arc<AtomicBool>,
}

impl ProviderActionLease {
    pub(crate) fn acquire(app: &AppState) -> Option<Self> {
        app.provider_action_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self {
                active: Arc::clone(&app.provider_action_active),
            })
    }
}

impl Drop for ProviderActionLease {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

fn current_timestamp() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn bounded_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(100).clamp(1, 1_000)
}

fn valid_correlation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn storage_list<T: Serialize>(result: Result<Vec<T>, crate::storage::StorageError>) -> Response {
    match result {
        Ok(items) => Json(ListResponse { items }).into_response(),
        Err(error) => {
            api_warn!(
                error_code = "STORAGE_QUERY_FAILED",
                error = %error,
                "control query failed"
            );
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "STORAGE_QUERY_FAILED",
                "운영 데이터를 읽지 못했습니다.",
                "방어 동작은 계속되지만 화면 데이터가 지연됩니다.",
                "SQLite 상태와 disk 여유 공간을 확인하십시오.",
            )
        }
    }
}

fn action_event(
    operation_id: String,
    occurred_at: String,
    action_name: &str,
    mode: GuardMode,
) -> GuardEvent {
    GuardEvent {
        schema_version: 1,
        event_id: format!("action-{operation_id}"),
        occurred_at,
        severity: Severity::Info,
        kind: "operator.action".to_owned(),
        summary: format!("운영자 명령 {action_name}을 적용했습니다."),
        reason_codes: Vec::new(),
        evidence: BTreeMap::new(),
        action: BTreeMap::from([("name".to_owned(), action_name.to_owned())]),
        result: BTreeMap::from([
            ("status".to_owned(), "applied".to_owned()),
            ("mode".to_owned(), mode_name(mode).to_owned()),
        ]),
        recovery: BTreeMap::new(),
    }
}

fn provider_event(
    operation_id: String,
    occurred_at: String,
    action_name: &str,
    mode: GuardMode,
    stage: guard_provider::ProviderStage,
) -> GuardEvent {
    GuardEvent {
        schema_version: 1,
        event_id: format!("provider-{operation_id}"),
        occurred_at,
        severity: if mode == GuardMode::EmergencyProxy {
            Severity::Critical
        } else {
            Severity::Info
        },
        kind: "provider.transaction".to_owned(),
        summary: format!(
            "Provider 명령 {action_name}이 {:?} 단계에 도달했습니다.",
            stage
        ),
        reason_codes: Vec::new(),
        evidence: BTreeMap::from([("read_back_stage".to_owned(), format!("{:?}", stage))]),
        action: BTreeMap::from([("name".to_owned(), action_name.to_owned())]),
        result: BTreeMap::from([("mode".to_owned(), mode_name(mode).to_owned())]),
        recovery: BTreeMap::from([(
            "method".to_owned(),
            "provider snapshot 역순 복구".to_owned(),
        )]),
    }
}

fn provider_started_event(
    operation_id: &str,
    occurred_at: String,
    action_name: &str,
) -> GuardEvent {
    GuardEvent {
        schema_version: 1,
        event_id: format!("provider-started-{operation_id}"),
        occurred_at,
        severity: Severity::Warning,
        kind: "provider.transaction_started".to_owned(),
        summary: format!("Provider 명령 {action_name}을 시작했습니다."),
        reason_codes: Vec::new(),
        evidence: BTreeMap::from([("operation_id".to_owned(), operation_id.to_owned())]),
        action: BTreeMap::from([("name".to_owned(), action_name.to_owned())]),
        result: BTreeMap::from([("status".to_owned(), "started".to_owned())]),
        recovery: BTreeMap::new(),
    }
}

pub(crate) fn record_provider_started(app: &AppState, operation_id: &str, action_name: &str) {
    publish_event(
        app,
        provider_started_event(operation_id, current_timestamp(), action_name),
    );
}

pub(crate) fn record_provider_stage(
    app: &AppState,
    operation_id: &str,
    action_name: &str,
    mode: GuardMode,
    stage: guard_provider::ProviderStage,
) {
    publish_event(
        app,
        provider_event(
            operation_id.to_owned(),
            current_timestamp(),
            action_name,
            mode,
            stage,
        ),
    );
}

pub(crate) fn publish_event(app: &AppState, event: GuardEvent) {
    if let Err(error) = app.storage.record_event(&event) {
        api_warn!(
            error_code = "EVENT_PERSISTENCE_FAILED",
            error = %error,
            event_id = %event.event_id,
            event_kind = %event.kind,
            "event persistence failed"
        );
    }
    app.notification.enqueue(&event);
    let _send_result = app.events.send(event);
}

pub(crate) fn record_provider_failure(
    app: &AppState,
    operation_id: &str,
    action_name: &str,
    error: &str,
) {
    let bounded_error = error.chars().take(256).collect::<String>();
    let event = GuardEvent {
        schema_version: 1,
        event_id: format!("provider-failed-{}", uuid::Uuid::new_v4().simple()),
        occurred_at: current_timestamp(),
        severity: Severity::Critical,
        kind: "provider.action_failed".to_owned(),
        summary: "Provider 조치가 완료되지 않아 현재 단계를 유지합니다.".to_owned(),
        reason_codes: Vec::new(),
        evidence: BTreeMap::from([
            ("operation_id".to_owned(), operation_id.to_owned()),
            ("error".to_owned(), bounded_error),
        ]),
        action: BTreeMap::from([("name".to_owned(), action_name.to_owned())]),
        result: BTreeMap::from([("status".to_owned(), "failed".to_owned())]),
        recovery: BTreeMap::from([(
            "next_action".to_owned(),
            "저장된 provider transaction 단계와 실제 DNS·firewall을 read-back하십시오.".to_owned(),
        )]),
    };
    publish_event(app, event);
}

const fn mode_name(mode: GuardMode) -> &'static str {
    match mode {
        GuardMode::Normal => "NORMAL",
        GuardMode::Watch => "WATCH",
        GuardMode::LocalGuard => "LOCAL_GUARD",
        GuardMode::EmergencyProxy => "EMERGENCY_PROXY",
        GuardMode::RecoveryReady => "RECOVERY_READY",
        GuardMode::Recovering => "RECOVERING",
        GuardMode::ManualHold => "MANUAL_HOLD",
    }
}

fn parse_mode(value: &str) -> Option<GuardMode> {
    match value {
        "NORMAL" => Some(GuardMode::Normal),
        "WATCH" => Some(GuardMode::Watch),
        "LOCAL_GUARD" => Some(GuardMode::LocalGuard),
        "EMERGENCY_PROXY" => Some(GuardMode::EmergencyProxy),
        "RECOVERY_READY" => Some(GuardMode::RecoveryReady),
        "RECOVERING" => Some(GuardMode::Recovering),
        "MANUAL_HOLD" => Some(GuardMode::ManualHold),
        _ => None,
    }
}

#[cfg(test)]
#[path = "api/tests.rs"]
mod tests;
