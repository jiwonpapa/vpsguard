//! loopback 관리 API와 embedded operations console을 제공합니다.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use guard_agent::CollectorState;
use guard_agent::os::OsSnapshot;
use guard_core::{GuardMode, GuardState};
use guard_system::AtomicJsonStore;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::telemetry::{TrafficAggregator, TrafficSummary};

const INDEX_HTML: &str = include_str!("../../../web/index.html");
const APP_CSS: &str = include_str!("../../../web/app.css");
const APP_JS: &str = include_str!("../../../web/app.js");

/// control API 공유 상태입니다.
#[derive(Debug)]
pub(crate) struct AppState {
    pub(crate) state: RwLock<GuardState>,
    pub(crate) state_store: AtomicJsonStore<GuardState>,
    pub(crate) traffic: Mutex<TrafficAggregator>,
    pub(crate) os_snapshot: RwLock<Option<OsSnapshot>>,
    pub(crate) action_token: String,
    pub(crate) completed_actions: Mutex<VecDeque<(String, GuardMode)>>,
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

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(styles))
        .route("/app.js", get(script))
        .route("/health/live", get(live))
        .route("/api/v1/status", get(status))
        .route("/api/v1/traffic/summary", get(traffic_summary))
        .route("/api/v1/resources", get(resources))
        .route("/api/v1/actions/manual-hold", post(manual_hold))
        .route("/api/v1/actions/resume-auto", post(resume_auto))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
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
    Json(ResourcesResponse {
        state: if os.is_some() {
            CollectorState::Live
        } else {
            CollectorState::Unavailable
        },
        os,
    })
}

async fn manual_hold(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_action(&app, &headers, true).await
}

async fn resume_auto(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    apply_action(&app, &headers, false).await
}

async fn apply_action(app: &Arc<AppState>, headers: &HeaderMap, hold: bool) -> Response {
    if !authorized(headers, &app.action_token) {
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
            state.hold(now)
        } else {
            state.resume(now)
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
    Json(ActionResponse {
        applied: true,
        mode: next.current_mode,
        operation_id,
    })
    .into_response()
}

fn authorized(headers: &HeaderMap, token: &str) -> bool {
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
    app.completed_actions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find_map(|(completed_id, mode)| (completed_id == operation_id).then_some(*mode))
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

#[cfg(test)]
#[path = "api/tests.rs"]
mod tests;
