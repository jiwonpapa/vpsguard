//! control 설정, telemetry receiver와 loopback API startup을 조율합니다.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_agent::os;
use guard_agent::services::{ServiceTargets, collect_services};
use guard_core::config::DetectionMode;
use guard_core::policy::{RouteRule, StaticLimits};
use guard_core::{
    Assessment, ConfigError, Detector, GuardConfig, GuardEvent, GuardMode, GuardState,
    PolicySnapshot, Severity, TransitionInput,
};
use guard_system::{AtomicJsonStore, StoreError};
use thiserror::Error;
use tokio::net::{TcpListener, UnixDatagram};
use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::{AppState, router};
use crate::auth::SessionStore;
use crate::provider::{ProviderController, ProviderControllerError};
use crate::storage::{SqliteStore, StorageError};
use crate::telemetry::{TelemetryEnvelope, TrafficAggregator};

const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// control startup·serve 실패입니다.
#[derive(Debug, Error)]
pub enum ControlError {
    /// 설정 파일 읽기 실패입니다.
    #[error("control 설정 파일 읽기 실패: {0}")]
    ReadConfig(#[from] std::io::Error),
    /// 설정 계약 실패입니다.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// 저장 상태 읽기 실패입니다.
    #[error(transparent)]
    StateStore(#[from] StoreError),
    /// SQLite 저장소 초기화 실패입니다.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Provider adapter 초기화 실패입니다.
    #[error(transparent)]
    Provider(#[from] ProviderControllerError),
    /// HTTP server 실패입니다.
    #[error("control HTTP server 실패: {0}")]
    Serve(String),
}

/// 설정을 읽고 loopback control API와 telemetry receiver를 실행합니다.
///
/// # Errors
///
/// 설정, 상태 저장 또는 listener 실패를 반환합니다.
pub async fn run_from_path(config_path: &Path) -> Result<(), ControlError> {
    let source = fs::read_to_string(config_path)?;
    let config = GuardConfig::from_toml(&source)?;
    let state_path = std::env::var_os("VPS_GUARD_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/vps-guard/state.json"));
    let store = AtomicJsonStore::new(state_path);
    let initial_state = if store.path().exists() {
        store.read()?
    } else {
        GuardState::normal("1970-01-01T00:00:00Z")
    };
    initial_state
        .validate()
        .map_err(|error| ControlError::Serve(error.to_string()))?;
    let storage = Arc::new(SqliteStore::open(&config.storage.database_path)?);
    let provider = Arc::new(Mutex::new(ProviderController::from_config(&config)?));
    let (events, _) = broadcast::channel(512);
    let app = Arc::new(AppState {
        state: RwLock::new(initial_state),
        state_store: store,
        traffic: Mutex::new(TrafficAggregator::new(config.edge.max_tracked_clients)),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        action_token: std::env::var("VPS_GUARD_ACTION_TOKEN").unwrap_or_default(),
        completed_actions: Mutex::new(VecDeque::with_capacity(1_024)),
        storage: Arc::clone(&storage),
        events,
        sessions: SessionStore::new(),
        provider,
        provider_action_active: Arc::new(AtomicBool::new(false)),
    });
    if app.action_token.is_empty() {
        warn!("VPS_GUARD_ACTION_TOKEN is empty; mutation and session endpoints are disabled");
    }
    spawn_os_collector(Arc::clone(&app));
    spawn_service_collectors(Arc::clone(&app), &config);
    let (storage_tx, storage_rx) = mpsc::channel(4_096);
    spawn_storage_writer(Arc::clone(&storage), storage_rx);
    spawn_telemetry_receiver(
        Arc::clone(&app),
        config.edge.telemetry_socket.clone(),
        storage_tx,
    )?;
    spawn_detection_loop(Arc::clone(&app), &config);
    spawn_retention(Arc::clone(&storage), &config);
    let listener = TcpListener::bind(config.ui.bind).await?;
    info!(listener = %config.ui.bind, "control API started");
    axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| ControlError::Serve(error.to_string()))
}

fn spawn_os_collector(app: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let result = tokio::task::spawn_blocking(|| os::collect(Path::new("/proc"))).await;
            match result {
                Ok(Ok(snapshot)) => *app.os_snapshot.write().await = Some(snapshot),
                Ok(Err(error)) => warn!(error = %error, "OS collector unavailable"),
                Err(error) => warn!(error = %error, "OS collector task failed"),
            }
        }
    });
}

fn spawn_service_collectors(app: Arc<AppState>, config: &GuardConfig) {
    let targets = ServiceTargets {
        nginx_status_url: config.collectors.nginx_status_url.clone(),
        php_fpm_status_url: config.collectors.php_fpm_status_url.clone(),
        mysql_address: config.collectors.mysql_address,
        redis_address: config.collectors.redis_address,
    };
    let timeout = Duration::from_millis(config.collectors.timeout_ms);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            *app.service_health.write().await = collect_services(&targets, timeout).await;
        }
    });
}

fn spawn_telemetry_receiver(
    app: Arc<AppState>,
    path: PathBuf,
    storage_tx: mpsc::Sender<TelemetryEnvelope>,
) -> Result<(), ControlError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        fs::remove_file(&path)?;
    }
    let socket = UnixDatagram::bind(&path)?;
    tokio::spawn(async move {
        let mut buffer = [0_u8; 4_096];
        loop {
            match socket.recv(&mut buffer).await {
                Ok(length) => {
                    match serde_json::from_slice::<TelemetryEnvelope>(&buffer[..length]) {
                        Ok(telemetry) => {
                            lock_traffic(&app).ingest(&telemetry);
                            if storage_tx.try_send(telemetry).is_err() {
                                warn!("traffic persistence queue full; sample dropped");
                            }
                        }
                        Err(error) => warn!(error = %error, "invalid telemetry datagram dropped"),
                    }
                }
                Err(error) => warn!(error = %error, "telemetry receive failed"),
            }
        }
    });
    Ok(())
}

fn spawn_storage_writer(
    storage: Arc<SqliteStore>,
    mut receiver: mpsc::Receiver<TelemetryEnvelope>,
) {
    tokio::spawn(async move {
        while let Some(telemetry) = receiver.recv().await {
            if let Err(error) = storage.record_traffic(&telemetry) {
                warn!(error = %error, "traffic sample persistence failed");
            }
        }
    });
}

fn spawn_detection_loop(app: Arc<AppState>, config: &GuardConfig) {
    let enforce = config.detection.mode == DetectionMode::Enforce;
    let policy_store = AtomicJsonStore::<PolicySnapshot>::new(config.edge.policy_path.clone());
    let max_body_bytes = config.edge.max_body_bytes;
    let max_tracked_clients = config.edge.max_tracked_clients;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_policy_refresh = None;
        loop {
            interval.tick().await;
            let policy_refresh_due =
                enforce && policy_renewal_due(last_policy_refresh, Instant::now());
            let resources_available = app.os_snapshot.read().await.is_some();
            let input = lock_traffic(&app).take_detection_input(resources_available);
            let occurred_at = current_timestamp();
            let current = app.state.read().await.clone();
            let Some(input) = input else {
                if policy_refresh_due
                    && let Some(refreshed) = write_policy_for_mode(
                        &policy_store,
                        current,
                        max_body_bytes,
                        max_tracked_clients,
                    )
                    .await
                    && persist_state(&app, &refreshed).await.is_ok()
                {
                    *app.state.write().await = refreshed;
                    last_policy_refresh = Some(Instant::now());
                }
                continue;
            };
            let assessment = Detector::assess(&input);
            let provider_verified = app.provider.try_lock().ok().is_some_and(|provider| {
                provider
                    .as_ref()
                    .is_some_and(ProviderController::recovery_ready)
            });
            let mut next = current.clone().transition(&TransitionInput {
                assessment: assessment.clone(),
                distributed_pressure: assessment.bot_likelihood >= 80,
                provider_verified,
                occurred_at: occurred_at.clone(),
            });
            if !enforce
                && matches!(
                    next.current_mode,
                    GuardMode::LocalGuard | GuardMode::EmergencyProxy
                )
            {
                next.current_mode = GuardMode::Watch;
            }
            if enforce
                && current.current_mode != GuardMode::EmergencyProxy
                && next.current_mode == GuardMode::EmergencyProxy
            {
                match run_provider_transaction(&app, false).await {
                    Ok(guard_provider::ProviderStage::Complete) => {}
                    Ok(stage) => {
                        warn!(?stage, "provider transaction stopped before completion");
                        keep_local_guard(&current, &mut next);
                    }
                    Err(error) => {
                        warn!(error, "automatic provider transaction unavailable");
                        keep_local_guard(&current, &mut next);
                    }
                }
            }
            if enforce
                && current.current_mode == GuardMode::EmergencyProxy
                && next.current_mode == GuardMode::Recovering
            {
                match run_provider_transaction(&app, true).await {
                    Ok(guard_provider::ProviderStage::Restored) => {}
                    Ok(stage) => {
                        warn!(?stage, "provider restore stopped before completion");
                        keep_emergency(&current, &mut next);
                    }
                    Err(error) => {
                        warn!(error, "automatic provider restore failed");
                        keep_emergency(&current, &mut next);
                    }
                }
            }
            let state_changed = next.current_mode != current.current_mode;
            if !state_changed && !policy_refresh_due {
                continue;
            }
            let mut policy_refreshed = false;
            if enforce {
                let Some(refreshed) =
                    write_policy_for_mode(&policy_store, next, max_body_bytes, max_tracked_clients)
                        .await
                else {
                    continue;
                };
                next = refreshed;
                policy_refreshed = true;
            }
            update_incident(&mut next);
            if persist_state(&app, &next).await.is_err() {
                continue;
            }
            *app.state.write().await = next.clone();
            if policy_refreshed {
                last_policy_refresh = Some(Instant::now());
            }
            if state_changed {
                let event = transition_event(&current, &next, &assessment, occurred_at);
                if let Err(error) = app.storage.record_event(&event) {
                    warn!(error = %error, "transition event persistence failed");
                }
                let _send_result = app.events.send(event);
            }
        }
    });
}

async fn write_policy_for_mode(
    policy_store: &AtomicJsonStore<PolicySnapshot>,
    mut state: GuardState,
    max_body_bytes: u64,
    max_tracked_clients: usize,
) -> Option<GuardState> {
    let policy_version = state.policy_version.saturating_add(1);
    let policy = match build_policy(
        state.current_mode,
        policy_version,
        max_body_bytes,
        max_tracked_clients,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            warn!(error = %error, "policy snapshot generation failed");
            return None;
        }
    };
    let policy_store = policy_store.clone();
    let write_result = tokio::task::spawn_blocking(move || policy_store.write(&policy)).await;
    if !matches!(write_result, Ok(Ok(()))) {
        warn!("policy snapshot write failed; state update deferred");
        return None;
    }
    state.policy_version = policy_version;
    Some(state)
}

fn policy_renewal_due(last_refresh: Option<Instant>, now: Instant) -> bool {
    last_refresh.is_none_or(|last| now.saturating_duration_since(last) >= POLICY_REFRESH_INTERVAL)
}

async fn run_provider_transaction(
    app: &Arc<AppState>,
    restore: bool,
) -> Result<guard_provider::ProviderStage, String> {
    let _lease = crate::api::ProviderActionLease::acquire(app)
        .ok_or_else(|| "PROVIDER_ACTION_IN_PROGRESS".to_owned())?;
    let provider = Arc::clone(&app.provider);
    tokio::task::spawn_blocking(move || {
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
                .enable(&format!("auto-{}", Uuid::new_v4()))
                .map_err(|error| error.to_string())
        }
    })
    .await
    .map_err(|error| format!("PROVIDER_TASK_FAILED: {error}"))?
}

fn keep_local_guard(current: &GuardState, next: &mut GuardState) {
    next.current_mode = GuardMode::LocalGuard;
    next.last_transition_at
        .clone_from(&current.last_transition_at);
}

fn keep_emergency(current: &GuardState, next: &mut GuardState) {
    next.current_mode = GuardMode::EmergencyProxy;
    next.last_transition_at
        .clone_from(&current.last_transition_at);
}

async fn persist_state(app: &AppState, state: &GuardState) -> Result<(), ()> {
    let store = app.state_store.clone();
    let value = state.clone();
    match tokio::task::spawn_blocking(move || store.write(&value)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            warn!(error = %error, "state persistence failed");
            Err(())
        }
        Err(error) => {
            warn!(error = %error, "state persistence task failed");
            Err(())
        }
    }
}

fn build_policy(
    mode: GuardMode,
    policy_version: u64,
    max_body_bytes: u64,
    max_tracked_clients: usize,
) -> Result<PolicySnapshot, guard_core::PolicyError> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let now = OffsetDateTime::now_utc();
    let route_rules = match mode {
        GuardMode::Normal => Vec::new(),
        GuardMode::Watch | GuardMode::Recovering => vec![RouteRule {
            route_class: "strict".to_owned(),
            requests_per_minute: 120,
        }],
        GuardMode::LocalGuard => vec![
            RouteRule {
                route_class: "strict".to_owned(),
                requests_per_minute: 30,
            },
            RouteRule {
                route_class: "upload".to_owned(),
                requests_per_minute: 15,
            },
        ],
        GuardMode::EmergencyProxy => vec![
            RouteRule {
                route_class: "strict".to_owned(),
                requests_per_minute: 10,
            },
            RouteRule {
                route_class: "upload".to_owned(),
                requests_per_minute: 5,
            },
        ],
        GuardMode::ManualHold => Vec::new(),
    };
    PolicySnapshot {
        schema_version: 1,
        policy_version,
        generated_at: now.format(&Rfc3339).unwrap_or_default(),
        expires_at: (now + time::Duration::minutes(10))
            .format(&Rfc3339)
            .unwrap_or_default(),
        mode,
        route_rules,
        client_rules: Vec::new(),
        static_limits: StaticLimits {
            max_body_bytes,
            max_tracked_clients,
        },
        content_sha256: String::new(),
    }
    .seal()
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod tests;

fn update_incident(state: &mut GuardState) {
    if matches!(
        state.current_mode,
        GuardMode::LocalGuard | GuardMode::EmergencyProxy
    ) && state.active_incident_id.is_none()
    {
        state.active_incident_id = Some(format!("incident-{}", Uuid::new_v4().simple()));
    } else if state.current_mode == GuardMode::Normal {
        state.active_incident_id = None;
    }
}

fn transition_event(
    previous: &GuardState,
    next: &GuardState,
    assessment: &Assessment,
    occurred_at: String,
) -> GuardEvent {
    GuardEvent {
        schema_version: 1,
        event_id: format!("event-{}", Uuid::new_v4().simple()),
        occurred_at,
        severity: if next.current_mode == GuardMode::EmergencyProxy {
            Severity::Critical
        } else if next.current_mode == GuardMode::Normal {
            Severity::Info
        } else {
            Severity::Warning
        },
        kind: "guard.mode_transition".to_owned(),
        summary: format!(
            "방어 모드가 {:?}에서 {:?}(으)로 전환됐습니다.",
            previous.current_mode, next.current_mode
        ),
        reason_codes: assessment.reason_codes.clone(),
        evidence: BTreeMap::from([
            (
                "bot_likelihood".to_owned(),
                assessment.bot_likelihood.to_string(),
            ),
            (
                "resource_cost".to_owned(),
                assessment.resource_cost.to_string(),
            ),
            ("confidence".to_owned(), assessment.confidence.to_string()),
        ]),
        action: BTreeMap::from([("mode".to_owned(), format!("{:?}", next.current_mode))]),
        result: BTreeMap::from([("policy_version".to_owned(), next.policy_version.to_string())]),
        recovery: BTreeMap::from([(
            "condition".to_owned(),
            "연속 안정 window 확인 후 단계적으로 해제".to_owned(),
        )]),
    }
}

fn spawn_retention(storage: Arc<SqliteStore>, config: &GuardConfig) {
    let detail_ms = config
        .retention
        .detail_hours
        .saturating_mul(60)
        .saturating_mul(60_000);
    let raw_ip_ms = config
        .retention
        .raw_ip_days
        .saturating_mul(24)
        .saturating_mul(60)
        .saturating_mul(60_000);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = unix_millis();
            if let Err(error) =
                storage.retain_since(now.saturating_sub(detail_ms), now.saturating_sub(raw_ip_ms))
            {
                warn!(error = %error, "retention maintenance failed");
            }
        }
    });
}

fn current_timestamp() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn lock_traffic(app: &AppState) -> std::sync::MutexGuard<'_, TrafficAggregator> {
    app.traffic
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        warn!("control shutdown signal handler failed");
    }
}
