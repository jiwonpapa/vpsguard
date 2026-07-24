//! 관리자 보호 제한의 인증된 HTTP plan·apply 경계입니다.

use guard_core::policy::ProtectionSettings;
use serde::Deserialize;

use super::*;
use crate::protection::{ProtectionApplyOutcome, ProtectionPlan, ProtectionSnapshot};

/// 보호 설정 plan 요청입니다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanRequest {
    settings: ProtectionSettings,
}

/// 보호 설정 적용 요청입니다.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyRequest {
    settings: ProtectionSettings,
    current_fingerprint: String,
    plan_hash: String,
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    schema_version: u32,
    settings: ProtectionSettings,
    policy_version: u64,
    fingerprint: String,
    edge_observed_policy_version: Option<u64>,
    edge_readback: &'static str,
    enforcement_active: bool,
}

#[derive(Debug, Serialize)]
struct ApplyResponse {
    applied: bool,
    operation_id: String,
    settings: ProtectionSettings,
    policy_version: u64,
    fingerprint: String,
    edge_observed_policy_version: Option<u64>,
    edge_readback: &'static str,
}

/// 현재 보호 제한과 Control·Edge version 상태를 반환합니다.
pub(super) async fn settings(State(app): State<Arc<AppState>>) -> Response {
    let snapshot = match app.protection.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return protection_policy_error(error),
    };
    let observed = match edge_observed_policy_version(&app).await {
        Ok(observed) => observed,
        Err(response) => return response,
    };
    Json(protection_settings_response(
        snapshot,
        observed,
        app.detection_mode == DetectionMode::Enforce,
    ))
    .into_response()
}

/// 인증·CSRF 확인 뒤 후보 설정의 검증된 diff plan을 반환합니다.
pub(super) async fn plan(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<PlanRequest>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    match app.protection.plan(request.settings) {
        Ok(plan) => Json::<ProtectionPlan>(plan).into_response(),
        Err(error) => protection_policy_error(error),
    }
}

/// 검증된 plan을 idempotency key와 현재 fingerprint 조건으로 원자 적용합니다.
pub(super) async fn apply(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ApplyRequest>,
) -> Response {
    if let Some(error) = mutation_authorization_error(&headers, &app).await {
        return error;
    }
    let Some(operation_id) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty() && value.len() <= 128)
        .map(ToOwned::to_owned)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "IDEMPOTENCY_KEY_REQUIRED",
            "Idempotency-Key가 필요합니다.",
            "보호 설정을 변경하지 않았습니다.",
            "128자 이하의 고유 operation ID로 다시 요청하십시오.",
        );
    };
    if let Some((completed_action, _)) = completed_action(&app, &operation_id)
        && completed_action != "protection_settings"
    {
        return idempotency_conflict();
    }

    let _operation = app.policy_operation.lock().await;
    let mode = app.state.read().await.current_mode;
    let outcome = match app
        .protection
        .apply(
            &operation_id,
            &request.current_fingerprint,
            &request.plan_hash,
            request.settings,
            mode,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return protection_policy_error(error),
    };
    let mut next = app.state.read().await.clone();
    if outcome.snapshot.policy_version > next.policy_version {
        next.policy_version = outcome.snapshot.policy_version;
        persist_policy_version(&app, &next, &operation_id).await;
        *app.state.write().await = next.clone();
    }
    if completed_action(&app, &operation_id).is_none() {
        remember_action(
            &app,
            operation_id.clone(),
            "protection_settings",
            next.current_mode,
        );
    }
    let now = current_timestamp();
    if let Err(error) = app.storage.record_action(
        &operation_id,
        &now,
        "protection_settings",
        mode_name(next.current_mode),
        if outcome.applied {
            "applied"
        } else {
            "unchanged"
        },
    ) {
        api_warn!(
            error_code = "PROTECTION_SETTINGS_AUDIT_FAILED",
            error = %error,
            operation_id,
            "protection settings audit persistence failed"
        );
    }
    publish_event(
        &app,
        action_event(
            operation_id.clone(),
            now,
            "protection_settings",
            next.current_mode,
        ),
    );
    let observed = match edge_observed_policy_version(&app).await {
        Ok(observed) => observed,
        Err(response) => return response,
    };
    Json(protection_apply_response(outcome, operation_id, observed)).into_response()
}

async fn persist_policy_version(app: &AppState, state: &GuardState, operation_id: &str) {
    let store = app.state_store.clone();
    let value = state.clone();
    match tokio::task::spawn_blocking(move || store.write(&value)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => api_warn!(
            error_code = "PROTECTION_STATE_METADATA_WRITE_FAILED",
            error = %error,
            operation_id,
            "policy is durable but state metadata persistence failed"
        ),
        Err(error) => api_warn!(
            error_code = "PROTECTION_STATE_METADATA_TASK_FAILED",
            error = %error,
            operation_id,
            "policy is durable but state metadata task failed"
        ),
    }
}

fn protection_settings_response(
    snapshot: ProtectionSnapshot,
    edge_observed_policy_version: Option<u64>,
    enforcement_active: bool,
) -> SettingsResponse {
    SettingsResponse {
        schema_version: 1,
        settings: snapshot.settings,
        policy_version: snapshot.policy_version,
        fingerprint: snapshot.fingerprint,
        edge_readback: edge_readback(snapshot.policy_version, edge_observed_policy_version),
        edge_observed_policy_version,
        enforcement_active,
    }
}

fn protection_apply_response(
    outcome: ProtectionApplyOutcome,
    operation_id: String,
    edge_observed_policy_version: Option<u64>,
) -> ApplyResponse {
    ApplyResponse {
        applied: outcome.applied,
        operation_id,
        settings: outcome.snapshot.settings,
        policy_version: outcome.snapshot.policy_version,
        fingerprint: outcome.snapshot.fingerprint,
        edge_readback: edge_readback(
            outcome.snapshot.policy_version,
            edge_observed_policy_version,
        ),
        edge_observed_policy_version,
    }
}

fn edge_readback(policy_version: u64, observed: Option<u64>) -> &'static str {
    match observed {
        Some(version) if version == policy_version => "observed",
        Some(version) if version > policy_version => "superseded",
        _ => "pending",
    }
}
