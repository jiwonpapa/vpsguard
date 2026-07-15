//! loopback 관리 API와 embedded operations console을 제공합니다.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use guard_agent::os::OsSnapshot;
use guard_agent::{CollectorHealth, CollectorState};
use guard_core::config::TlsManagementMode;
use guard_core::{GuardEvent, GuardMode, GuardState, Severity};
use guard_system::{
    AtomicJsonStore, CertbotPlanError, TlsManagementSnapshot, build_certbot_assisted_plan,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::{BootstrapStore, SessionStore, UiAccessPolicy};
use crate::provider::ProviderController;
use crate::storage::{ClientRow, EventRow, RouteRow, SqliteStore, StorageHealthSnapshot};
use crate::telemetry::{TrafficAggregator, TrafficSummary};

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
    pub(crate) tls_management: RwLock<TlsManagementSnapshot>,
    pub(crate) tls_plan_mode: TlsManagementMode,
    pub(crate) tls_plan_domains: Vec<String>,
    pub(crate) bootstrap: BootstrapStore,
    pub(crate) completed_actions: Mutex<VecDeque<(String, String, GuardMode)>>,
    pub(crate) storage: Arc<SqliteStore>,
    pub(crate) events: broadcast::Sender<GuardEvent>,
    pub(crate) sessions: SessionStore,
    pub(crate) access: UiAccessPolicy,
    pub(crate) provider: Arc<Mutex<Option<ProviderController>>>,
    pub(crate) provider_action_active: Arc<AtomicBool>,
}

/// overview 상태 응답입니다.
#[derive(Debug, Serialize)]
struct StatusResponse {
    schema_version: u32,
    mode: GuardMode,
    manual_hold: bool,
    policy_version: u64,
    last_transition_at: String,
    reasons: Vec<&'static str>,
    edge: &'static str,
    origin: &'static str,
    agent: CollectorState,
    provider: String,
    tls: String,
    tls_management: TlsManagementSnapshot,
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
    impact: &'static str,
    next_action: &'static str,
    retriable: bool,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    login_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsPlanRequest {
    email: String,
}

pub(crate) fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/traffic/summary", get(traffic_summary))
        .route("/api/v1/traffic/series", get(traffic_series))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/routes", get(routes))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/events", get(event_stream))
        .route("/api/v1/resources", get(resources))
        .route("/api/v1/tls/assisted-plan", post(tls_assisted_plan))
        .route("/api/v1/actions/manual-hold", post(manual_hold))
        .route("/api/v1/actions/resume-auto", post(resume_auto))
        .route("/api/v1/actions/emergency-proxy", post(emergency_proxy))
        .route("/api/v1/actions/provider-restore", post(provider_restore))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_session,
        ));
    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(styles))
        .route("/assets/app.js", get(script))
        .route("/health/live", get(live))
        .route("/api/v1/session", get(current_session).post(create_session))
        .merge(protected)
        .fallback(index)
        .layer(DefaultBodyLimit::max(16 * 1_024))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            enforce_management_host,
        ))
        .with_state(state)
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
    if !app.sessions.authenticate(request.headers()) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_AUTH_REQUIRED",
            "유효한 운영 session이 필요합니다.",
            "관리 데이터와 운영 명령을 제공하지 않았습니다.",
            "local 단회 로그인 코드로 session을 발급하십시오.",
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
        _ => vec!["최근 요청 비용과 자원 압력을 상세 관찰 중입니다."],
    };
    let provider = match app.provider.try_lock() {
        Ok(guard) => guard
            .as_ref()
            .map_or_else(|| "unavailable".to_owned(), ProviderController::status),
        Err(TryLockError::WouldBlock) => "running".to_owned(),
        Err(TryLockError::Poisoned(error)) => error
            .into_inner()
            .as_ref()
            .map_or_else(|| "unavailable".to_owned(), ProviderController::status),
    };
    let tls_management = app.tls_management.read().await.clone();
    Json(StatusResponse {
        schema_version: 1,
        mode: state.current_mode,
        manual_hold: state.manual_hold,
        policy_version: state.policy_version,
        last_transition_at: state.last_transition_at.clone(),
        reasons,
        edge: "live",
        origin: "unknown",
        agent,
        provider,
        tls: tls_management.health.as_str().to_owned(),
        tls_management,
    })
}

async fn traffic_summary(State(app): State<Arc<AppState>>) -> Json<TrafficSummary> {
    Json(lock_traffic(&app).summary())
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

async fn tls_assisted_plan(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<TlsPlanRequest>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app) {
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

async fn incidents(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    storage_list::<EventRow>(app.storage.events(bounded_limit(query.limit)))
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
    let Some((csrf_token, expires_in_seconds)) = app.sessions.resume(&headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_AUTH_REQUIRED",
            "유효한 운영 session이 없습니다.",
            "CSRF token을 복원하지 않았습니다.",
            "local 단회 로그인 코드로 session을 발급하십시오.",
        );
    };
    Json(SessionResponse {
        csrf_token,
        expires_in_seconds,
    })
    .into_response()
}

async fn create_session(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if !app.access.accepts_origin(&headers) {
        return api_error(
            StatusCode::FORBIDDEN,
            "MANAGEMENT_ORIGIN_INVALID",
            "요청 Origin이 관리 주소와 일치하지 않습니다.",
            "운영 session을 생성하지 않았습니다.",
            "설정된 HTTPS 관리 주소에서 다시 시도하십시오.",
        );
    }
    let valid_shape = request.login_code.len() == 64
        && request
            .login_code
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    if !valid_shape || !app.bootstrap.consume(&request.login_code) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "LOGIN_CODE_REJECTED",
            "로그인 code가 유효하지 않습니다.",
            "운영 session을 생성하지 않았습니다.",
            "root에서 새 단회 code를 발급한 뒤 만료 전에 다시 시도하십시오.",
        );
    }
    let issued = app.sessions.issue(app.access.secure_cookie());
    (
        [(header::SET_COOKIE, issued.set_cookie)],
        Json(SessionResponse {
            csrf_token: issued.csrf_token,
            expires_in_seconds: app.sessions.ttl_seconds(),
        }),
    )
        .into_response()
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
    if let Some(error) = mutation_authorization_error(headers, app) {
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
            controller.restore().map_err(|error| error.to_string())
        } else {
            controller
                .enable(&operation_for_task)
                .map_err(|error| error.to_string())
        }
    })
    .await;
    let stage = match provider_result {
        Ok(Ok(stage)) => stage,
        Ok(Err(error)) => {
            tracing::warn!(error, operation_id, "provider action failed");
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
            tracing::warn!(error = %error, "provider task failed");
            record_provider_failure(app, &operation_id, action_name, &error.to_string());
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
        tracing::warn!(error = %error, "provider audit persistence failed");
    }
    let event = provider_event(
        operation_id.clone(),
        now,
        action_name,
        next.current_mode,
        stage,
    );
    if let Err(error) = app.storage.record_event(&event) {
        tracing::warn!(error = %error, "provider event persistence failed");
    }
    let _send_result = app.events.send(event);
    Json(ActionResponse {
        applied: true,
        mode: next.current_mode,
        operation_id,
    })
    .into_response()
}

async fn apply_action(app: &Arc<AppState>, headers: &HeaderMap, hold: bool) -> Response {
    if let Some(error) = mutation_authorization_error(headers, app) {
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
        tracing::warn!(error = %error, operation_id, "action audit persistence failed");
    }
    let event = action_event(operation_id.clone(), now, action_name, next.current_mode);
    if let Err(error) = app.storage.record_event(&event) {
        tracing::warn!(error = %error, "action event persistence failed");
    }
    let _send_result = app.events.send(event);
    Json(ActionResponse {
        applied: true,
        mode: next.current_mode,
        operation_id,
    })
    .into_response()
}

fn mutation_authorization_error(headers: &HeaderMap, app: &AppState) -> Option<Response> {
    if !app.access.accepts_origin(headers) {
        return Some(api_error(
            StatusCode::FORBIDDEN,
            "MANAGEMENT_ORIGIN_INVALID",
            "요청 Origin이 관리 주소와 일치하지 않습니다.",
            "운영 상태를 변경하지 않았습니다.",
            "설정된 HTTPS 관리 주소에서 다시 시도하십시오.",
        ));
    }
    if !app.sessions.authorize(headers) {
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

fn api_error(
    status: StatusCode,
    code: &'static str,
    problem: &'static str,
    impact: &'static str,
    next_action: &'static str,
) -> Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail {
                code,
                problem,
                impact,
                next_action,
                retriable: true,
            },
        }),
    )
        .into_response()
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

fn storage_list<T: Serialize>(result: Result<Vec<T>, crate::storage::StorageError>) -> Response {
    match result {
        Ok(items) => Json(ListResponse { items }).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "control query failed");
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
    if let Err(storage_error) = app.storage.record_event(&event) {
        tracing::warn!(error = %storage_error, "provider failure event persistence failed");
    }
    let _send_result = app.events.send(event);
}

const fn mode_name(mode: GuardMode) -> &'static str {
    match mode {
        GuardMode::Normal => "NORMAL",
        GuardMode::Watch => "WATCH",
        GuardMode::LocalGuard => "LOCAL_GUARD",
        GuardMode::EmergencyProxy => "EMERGENCY_PROXY",
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
        "RECOVERING" => Some(GuardMode::Recovering),
        "MANUAL_HOLD" => Some(GuardMode::ManualHold),
        _ => None,
    }
}

#[cfg(test)]
#[path = "api/tests.rs"]
mod tests;
