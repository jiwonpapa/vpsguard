//! loopback 관리 API와 embedded operations console을 제공합니다.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use guard_agent::os::OsSnapshot;
use guard_agent::{CollectorHealth, CollectorState};
use guard_core::{GuardEvent, GuardMode, GuardState, Severity};
use guard_system::AtomicJsonStore;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::SessionStore;
use crate::storage::{ClientRow, EventRow, RouteRow, SqliteStore};
use crate::telemetry::{TrafficAggregator, TrafficSummary};

const INDEX_HTML: &str = include_str!("../../../web/dist/index.html");
const APP_CSS: &str = include_str!("../../../web/dist/assets/app.css");
const APP_JS: &str = include_str!("../../../web/dist/assets/app.js");

/// control API 공유 상태입니다.
#[derive(Debug)]
pub(crate) struct AppState {
    pub(crate) state: RwLock<GuardState>,
    pub(crate) state_store: AtomicJsonStore<GuardState>,
    pub(crate) traffic: Mutex<TrafficAggregator>,
    pub(crate) os_snapshot: RwLock<Option<OsSnapshot>>,
    pub(crate) service_health: RwLock<Vec<CollectorHealth>>,
    pub(crate) action_token: String,
    pub(crate) completed_actions: Mutex<VecDeque<(String, GuardMode)>>,
    pub(crate) storage: Arc<SqliteStore>,
    pub(crate) events: broadcast::Sender<GuardEvent>,
    pub(crate) sessions: SessionStore,
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
    provider: &'static str,
    tls: &'static str,
}

/// resource endpoint 응답입니다.
#[derive(Debug, Serialize)]
struct ResourcesResponse {
    state: CollectorState,
    os: Option<OsSnapshot>,
    services: Vec<CollectorHealth>,
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

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/app.css", get(styles))
        .route("/assets/app.js", get(script))
        .route("/health/live", get(live))
        .route("/api/v1/status", get(status))
        .route("/api/v1/traffic/summary", get(traffic_summary))
        .route("/api/v1/traffic/series", get(traffic_series))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/routes", get(routes))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/events", get(event_stream))
        .route("/api/v1/resources", get(resources))
        .route("/api/v1/session", post(create_session))
        .route("/api/v1/actions/manual-hold", post(manual_hold))
        .route("/api/v1/actions/resume-auto", post(resume_auto))
        .fallback(index)
        .with_state(state)
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
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
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
        provider: "unavailable",
        tls: "unknown",
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
    })
}

async fn traffic_series(
    State(app): State<Arc<AppState>>,
    Query(query): Query<SeriesQuery>,
) -> Response {
    let since = query.since_unix_ms.unwrap_or_else(|| {
        unix_millis().saturating_sub(24_u64.saturating_mul(60).saturating_mul(60_000))
    });
    storage_list(app.storage.series(since))
}

async fn clients(State(app): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    storage_list::<ClientRow>(app.storage.clients(bounded_limit(query.limit)))
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

async fn create_session(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorized_token(&headers, &app.action_token) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_AUTH_REQUIRED",
            "bootstrap token이 없거나 일치하지 않습니다.",
            "운영 session을 생성하지 않았습니다.",
            "VPS_GUARD_ACTION_TOKEN과 X-VPSGuard-Token을 확인하십시오.",
        );
    }
    let issued = app.sessions.issue(false);
    (
        [(header::SET_COOKIE, issued.set_cookie)],
        Json(SessionResponse {
            csrf_token: issued.csrf_token,
            expires_in_seconds: 30 * 60,
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

async fn apply_action(app: &Arc<AppState>, headers: &HeaderMap, hold: bool) -> Response {
    if !authorized(headers, app) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "ACTION_AUTH_REQUIRED",
            "운영 명령 token이 없거나 일치하지 않습니다.",
            "방어 상태를 변경하지 않았습니다.",
            "VPS_GUARD_ACTION_TOKEN과 X-VPSGuard-Token을 확인하십시오.",
        );
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
    if let Some(mode) = completed_action(app, &operation_id) {
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
    remember_action(app, operation_id.clone(), next.current_mode);
    let action_name = if hold { "manual_hold" } else { "resume_auto" };
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

fn authorized(headers: &HeaderMap, app: &AppState) -> bool {
    authorized_token(headers, &app.action_token) || app.sessions.authorize(headers)
}

fn authorized_token(headers: &HeaderMap, token: &str) -> bool {
    !token.is_empty()
        && headers
            .get("x-vpsguard-token")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|candidate| candidate == token)
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

fn completed_action(app: &AppState, operation_id: &str) -> Option<GuardMode> {
    let memory_mode = app
        .completed_actions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find_map(|(completed_id, mode)| (completed_id == operation_id).then_some(*mode));
    memory_mode.or_else(|| {
        app.storage
            .completed_action(operation_id)
            .ok()
            .flatten()
            .as_deref()
            .and_then(parse_mode)
    })
}

fn remember_action(app: &AppState, operation_id: String, mode: GuardMode) {
    const MAX_COMPLETED_ACTIONS: usize = 1_024;
    let mut actions = app
        .completed_actions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if actions.len() == MAX_COMPLETED_ACTIONS {
        actions.pop_front();
    }
    actions.push_back((operation_id, mode));
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
