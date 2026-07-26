//! 관리자 보호 제한의 인증된 HTTP plan·apply 경계입니다.

use guard_core::policy::ProtectionSettings;
use serde::Deserialize;
use sha2::{Digest, Sha256};

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TemporaryBlockRequest {
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
struct TemporaryBlockResponse {
    applied: bool,
    operation_id: String,
    client_ip: IpAddr,
    policy_version: u64,
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
    if let Some(error) =
        mutation_authorization_error(&headers, &app, AdminPermission::Operate).await
    {
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
    if let Some(error) =
        mutation_authorization_error(&headers, &app, AdminPermission::Operate).await
    {
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

/// 인증된 운영자가 IP에 TTL 거부 규칙을 적용합니다.
pub(super) async fn block_client(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client_ip): Path<String>,
    Json(request): Json<TemporaryBlockRequest>,
) -> Response {
    mutate_client_rule(&app, &headers, &client_ip, Some(request.ttl_seconds)).await
}

/// 인증된 운영자가 IP의 TTL 거부 규칙을 즉시 해제합니다.
pub(super) async fn unblock_client(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client_ip): Path<String>,
) -> Response {
    mutate_client_rule(&app, &headers, &client_ip, None).await
}

async fn mutate_client_rule(
    app: &Arc<AppState>,
    headers: &HeaderMap,
    client_ip: &str,
    ttl_seconds: Option<u64>,
) -> Response {
    if let Some(error) = mutation_authorization_error(headers, app, AdminPermission::Operate).await
    {
        return error;
    }
    let Ok(client_ip) = client_ip.parse::<IpAddr>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "CLIENT_IP_INVALID",
            "클라이언트 주소 형식이 올바르지 않습니다.",
            "Edge client rule을 변경하지 않았습니다.",
            "클라이언트 목록의 IPv4 또는 IPv6 주소를 다시 선택하십시오.",
        );
    };
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
            "Edge client rule을 변경하지 않았습니다.",
            "128자 이하의 고유 operation ID로 다시 요청하십시오.",
        );
    };
    let _operation = app.policy_operation.lock().await;
    let action = client_rule_action(client_ip, ttl_seconds);
    if let Some((completed, _)) = completed_action(app, &operation_id) {
        if completed != action {
            return idempotency_conflict();
        }
        let snapshot = match app.protection.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return protection_policy_error(error),
        };
        return Json(TemporaryBlockResponse {
            applied: false,
            operation_id,
            client_ip,
            policy_version: snapshot.policy_version,
        })
        .into_response();
    }

    let mode = app.state.read().await.current_mode;
    let snapshot = match ttl_seconds {
        Some(ttl_seconds) => {
            app.protection
                .block_client(client_ip, ttl_seconds, mode)
                .await
        }
        None => app.protection.unblock_client(client_ip, mode).await,
    };
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => return protection_policy_error(error),
    };
    let mut next = app.state.read().await.clone();
    next.policy_version = next.policy_version.max(snapshot.policy_version);
    persist_policy_version(app, &next, &operation_id).await;
    *app.state.write().await = next.clone();
    remember_action(app, operation_id.clone(), &action, next.current_mode);
    let now = current_timestamp();
    if let Err(error) = app.storage.record_action(
        &operation_id,
        &now,
        &action,
        mode_name(next.current_mode),
        "applied",
    ) {
        api_warn!(
            error_code = "CLIENT_RULE_AUDIT_FAILED",
            error = %error,
            operation_id,
            "temporary client rule audit persistence failed"
        );
    }
    publish_event(
        app,
        action_event(operation_id.clone(), now, &action, next.current_mode),
    );
    Json(TemporaryBlockResponse {
        applied: true,
        operation_id,
        client_ip,
        policy_version: snapshot.policy_version,
    })
    .into_response()
}

fn client_rule_action(client_ip: IpAddr, ttl_seconds: Option<u64>) -> String {
    let action = if ttl_seconds.is_some() {
        "client_block"
    } else {
        "client_unblock"
    };
    let digest = Sha256::digest(format!("{client_ip}:{ttl_seconds:?}").as_bytes());
    let fingerprint = format!("{digest:x}");
    format!("{action}:{}", &fingerprint[..16])
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
