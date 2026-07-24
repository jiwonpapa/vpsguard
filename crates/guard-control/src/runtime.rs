//! control 설정, telemetry receiver와 loopback API startup을 조율합니다.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_agent::os;
use guard_agent::services::{
    ServiceProbe, ServiceTarget, ServiceTargets, ServiceTargetsError, collect_services,
    merge_service_history,
};
use guard_core::config::{DetectionMode, ServiceCollectorKind};
use guard_core::correlation::LOG_SCHEMA_VERSION;
use guard_core::{
    Assessment, ConfigError, Detector, GuardConfig, GuardEvent, GuardMode, GuardState,
    HostPressure, Severity, TransitionInput,
};
use guard_system::{AtomicJsonStore, StoreError, inspect_tls_management};
use thiserror::Error;
use tokio::net::{TcpListener, UnixDatagram};
use tokio::sync::{RwLock, broadcast, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

macro_rules! control_warn {
    ($error_code:literal, $($field:tt)*) => {
        warn!(
            log_schema_version = LOG_SCHEMA_VERSION,
            component = "guard-control",
            error_code = $error_code,
            $($field)*
        )
    };
}

use crate::admin_socket::spawn_admin_socket;
use crate::api::{AppState, router};
use crate::auth::{AuthError, BootstrapStore, SessionStore, UiAccessPolicy};
use crate::auth_store::{AuthRepository, AuthStoreError};
use crate::firewall::FirewallManager;
use crate::notification;
use crate::protection::{ProtectionPolicyError, ProtectionPolicyManager};
use crate::provider::{ProviderController, ProviderControllerError};
use crate::storage::{RetentionCutoffs, SqliteStore, StorageError, TRAFFIC_QUEUE_CAPACITY};
use crate::telemetry::{TelemetryEnvelope, TrafficAggregator};

const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const TLS_INSPECTION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const STORAGE_BATCH_SIZE: usize = 256;
const STORAGE_BATCH_WAIT: Duration = Duration::from_millis(25);
const STORAGE_HEALTH_INTERVAL: Duration = Duration::from_secs(30);
const STORAGE_RETENTION_INTERVAL: Duration = Duration::from_secs(10);

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
    /// 관리자 인증 저장소 초기화 실패입니다.
    #[error(transparent)]
    AuthStore(#[from] AuthStoreError),
    /// 관리자 인증 service 초기화 실패입니다.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// Provider adapter 초기화 실패입니다.
    #[error(transparent)]
    Provider(#[from] ProviderControllerError),
    /// 관리자 보호 policy 초기화 실패입니다.
    #[error(transparent)]
    Protection(#[from] ProtectionPolicyError),
    /// 핵심 service collector 초기화 실패입니다.
    #[error(transparent)]
    Collector(#[from] ServiceTargetsError),
    /// HTTP server 실패입니다.
    #[error("control HTTP server 실패: {0}")]
    Serve(String),
    /// local 관리자 socket 준비 실패입니다.
    #[error("local 관리자 socket 실패: {0}")]
    AdminSocket(String),
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
    let mut initial_state = if store.path().exists() {
        store.read()?
    } else {
        GuardState::normal("1970-01-01T00:00:00Z")
    };
    initial_state
        .validate()
        .map_err(|error| ControlError::Serve(error.to_string()))?;
    let protection = Arc::new(ProtectionPolicyManager::load(
        config.edge.policy_path.clone(),
        initial_state.policy_version,
        initial_state.current_mode,
        config.edge.max_body_bytes,
        config.edge.max_tracked_clients,
    )?);
    let restored_policy_version = protection.snapshot()?.policy_version;
    if restored_policy_version > initial_state.policy_version {
        initial_state.policy_version = restored_policy_version;
        store.write(&initial_state)?;
    }
    let storage = Arc::new(SqliteStore::open(
        &config.storage.database_path,
        config.storage.max_database_bytes,
        config.storage.min_disk_free_bytes,
        config.retention.raw_ip_days > 0,
    )?);
    let auth_repository = Arc::new(AuthRepository::open(&config.storage.database_path)?);
    let sessions = SessionStore::from_ui_config(auth_repository, &config.ui)?;
    let provider = Arc::new(Mutex::new(ProviderController::from_config(&config)?));
    let notification = match notification::start(&config.notifications, Arc::clone(&storage)) {
        Ok(handle) => handle,
        Err(error) => {
            control_warn!(
                "CONTROL_NOTIFICATION_DEGRADED",
                error = %error,
                "notification initialization failed without blocking control startup"
            );
            notification::NotificationHandle::unavailable(
                &config.notifications,
                Arc::clone(&storage),
                &error,
            )
        }
    };
    let initial_tls = {
        let tls = config.tls.clone();
        tokio::task::spawn_blocking(move || inspect_tls_management(&tls))
            .await
            .map_err(|error| ControlError::Serve(format!("TLS 검사 task 실패: {error}")))?
    };
    let (events, _) = broadcast::channel(512);
    let app = Arc::new(AppState {
        state: RwLock::new(initial_state),
        state_store: store,
        traffic: Mutex::new(TrafficAggregator::with_live_window(
            config.edge.max_tracked_clients,
            usize::try_from(config.retention.live_seconds).unwrap_or(86_400),
        )),
        os_snapshot: RwLock::new(None),
        service_health: RwLock::new(Vec::new()),
        inspection_mode: config.detection.inspection,
        detection_mode: config.detection.mode,
        security: config.security.clone(),
        waf: config.waf.clone(),
        tls_management: RwLock::new(initial_tls),
        tls_plan_mode: config.tls.management,
        tls_plan_domains: tls_plan_domains(&config),
        bootstrap: BootstrapStore::new(),
        completed_actions: Mutex::new(VecDeque::with_capacity(1_024)),
        storage: Arc::clone(&storage),
        events,
        notification,
        protection,
        policy_operation: tokio::sync::Mutex::new(()),
        sessions: Arc::new(sessions),
        access: UiAccessPolicy::from_config(&config.ui),
        firewall: Arc::new(FirewallManager::system(
            config.firewall.mode,
            config.firewall.ssh_port,
            config.ui.privileged_socket.clone(),
        )),
        provider,
        provider_action_active: Arc::new(AtomicBool::new(false)),
        request_ids: guard_core::correlation::RequestIdGenerator::new(),
    });
    spawn_admin_socket(Arc::clone(&app), config.ui.admin_socket.clone())
        .map_err(|error| ControlError::AdminSocket(error.to_string()))?;
    spawn_os_collector(Arc::clone(&app));
    spawn_service_collectors(Arc::clone(&app), &config)?;
    spawn_tls_inspection(Arc::clone(&app), config.tls.clone());
    let (storage_tx, storage_rx) = mpsc::channel(TRAFFIC_QUEUE_CAPACITY);
    spawn_storage_writer(Arc::clone(&storage), storage_rx)
        .map_err(|error| ControlError::Serve(format!("storage writer thread 실패: {error}")))?;
    spawn_storage_health(Arc::clone(&storage));
    spawn_telemetry_receiver(
        Arc::clone(&app),
        config.edge.telemetry_socket.clone(),
        storage_tx,
    )?;
    spawn_detection_loop(Arc::clone(&app), &config);
    spawn_retention(Arc::clone(&storage), &config);
    let listener = TcpListener::bind(config.ui.bind).await?;
    info!(
        log_schema_version = LOG_SCHEMA_VERSION,
        component = "guard-control",
        event_code = "CONTROL_STARTED",
        listener = %config.ui.bind,
        "control API started"
    );
    axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| ControlError::Serve(error.to_string()))
}

fn tls_plan_domains(config: &GuardConfig) -> Vec<String> {
    let mut domains = config
        .tls
        .certificates
        .iter()
        .flat_map(|certificate| certificate.domains.iter().cloned())
        .collect::<Vec<_>>();
    if domains.is_empty() {
        domains.extend(
            config
                .edge
                .allowed_hosts
                .iter()
                .filter(|domain| !domain.starts_with("*."))
                .cloned(),
        );
    }
    domains.sort_unstable();
    domains.dedup();
    domains.truncate(16);
    domains
}

fn spawn_tls_inspection(app: Arc<AppState>, tls: guard_core::config::TlsConfig) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TLS_INSPECTION_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let config = tls.clone();
            match tokio::task::spawn_blocking(move || inspect_tls_management(&config)).await {
                Ok(snapshot) => *app.tls_management.write().await = snapshot,
                Err(error) => control_warn!(
                    "CONTROL_TLS_INSPECTION_TASK_FAILED",
                    error = %error,
                    "TLS inspection task failed"
                ),
            }
        }
    });
}

fn spawn_os_collector(app: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut previous_cpu = None;
        loop {
            interval.tick().await;
            let previous = previous_cpu;
            let result = tokio::task::spawn_blocking(move || {
                os::collect_with_previous(Path::new("/proc"), previous)
            })
            .await;
            match result {
                Ok(Ok((snapshot, current_cpu))) => {
                    previous_cpu = Some(current_cpu);
                    *app.os_snapshot.write().await = Some(snapshot);
                }
                Ok(Err(error)) => {
                    previous_cpu = None;
                    *app.os_snapshot.write().await = None;
                    control_warn!(
                        "CONTROL_OS_COLLECTOR_UNAVAILABLE",
                        error = %error,
                        "OS collector unavailable"
                    );
                }
                Err(error) => {
                    previous_cpu = None;
                    *app.os_snapshot.write().await = None;
                    control_warn!(
                        "CONTROL_OS_COLLECTOR_TASK_FAILED",
                        error = %error,
                        "OS collector task failed"
                    );
                }
            }
        }
    });
}

fn host_pressure(snapshot: Option<&os::OsSnapshot>) -> HostPressure {
    let Some(snapshot) = snapshot else {
        return HostPressure::unavailable();
    };
    let cpu = snapshot
        .cpu_usage_percent
        .map_or(0, |percent| pressure_score(u64::from(percent), 70, 85, 95));
    let load_ratio = if snapshot.load_1m.is_finite() && snapshot.load_1m >= 0.0 {
        (snapshot.load_1m * 100.0 / f64::from(snapshot.logical_cpu_count.max(1))) as u64
    } else {
        0
    };
    let load = pressure_score(load_ratio, 75, 125, 200);
    let memory = used_percent(snapshot.memory_total_bytes, snapshot.memory_available_bytes)
        .map_or(0, |percent| pressure_score(percent, 75, 90, 97));
    let swap = used_percent(snapshot.swap_total_bytes, snapshot.swap_free_bytes)
        .map_or(0, |percent| pressure_score(percent, 25, 60, 90));
    HostPressure::available(cpu.max(load).max(memory).max(swap))
}

const fn pressure_score(value: u64, warning: u64, high: u64, critical: u64) -> u8 {
    if value >= critical {
        100
    } else if value >= high {
        80
    } else if value >= warning {
        50
    } else {
        0
    }
}

fn used_percent(total: u64, available: u64) -> Option<u64> {
    (total > 0).then(|| {
        total
            .saturating_sub(available)
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or_default()
    })
}

fn spawn_service_collectors(
    app: Arc<AppState>,
    config: &GuardConfig,
) -> Result<(), ServiceTargetsError> {
    let timeout = Duration::from_millis(config.collectors.timeout_ms);
    let targets = ServiceTargets::new(
        config.collectors.cgroup_root.clone(),
        configured_service_targets(config),
        timeout,
    )?;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut previous = Vec::new();
        loop {
            interval.tick().await;
            let mut current = collect_services(&targets).await;
            merge_service_history(
                &previous,
                &mut current,
                unix_millis(),
                Duration::from_secs(30),
            );
            *app.service_health.write().await = current.clone();
            previous = current;
        }
    });
    Ok(())
}

fn configured_service_targets(config: &GuardConfig) -> Vec<ServiceTarget> {
    let mut targets = config
        .collectors
        .services
        .iter()
        .map(|service| {
            let probe = match service.kind {
                ServiceCollectorKind::Nginx => ServiceProbe::Nginx {
                    status_url: service.status_url.clone().unwrap_or_default(),
                },
                ServiceCollectorKind::Apache => ServiceProbe::Apache {
                    status_url: service.status_url.clone().unwrap_or_default(),
                },
                ServiceCollectorKind::PhpFpm => ServiceProbe::PhpFpm {
                    status_url: service.status_url.clone().unwrap_or_default(),
                },
                ServiceCollectorKind::Mysql => ServiceProbe::Mysql {
                    credential_file: service.credential_file.clone().unwrap_or_default(),
                },
                ServiceCollectorKind::Redis => service.address.map_or_else(
                    || ServiceProbe::RedisCredential {
                        credential_file: service.credential_file.clone().unwrap_or_default(),
                    },
                    |address| ServiceProbe::RedisAddress { address },
                ),
            };
            ServiceTarget {
                name: service.name.clone(),
                unit: Some(service.unit.clone()),
                cgroup_path: Some(
                    service
                        .cgroup_path
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("system.slice").join(&service.unit)),
                ),
                probe,
            }
        })
        .collect::<Vec<_>>();
    if let Some(status_url) = config.collectors.nginx_status_url.clone() {
        targets.push(ServiceTarget {
            name: "nginx".to_owned(),
            unit: None,
            cgroup_path: None,
            probe: ServiceProbe::Nginx { status_url },
        });
    }
    if let Some(status_url) = config.collectors.php_fpm_status_url.clone() {
        targets.push(ServiceTarget {
            name: "php_fpm".to_owned(),
            unit: None,
            cgroup_path: None,
            probe: ServiceProbe::PhpFpm { status_url },
        });
    }
    if let Some(address) = config.collectors.mysql_address {
        targets.push(ServiceTarget {
            name: "mysql".to_owned(),
            unit: None,
            cgroup_path: None,
            probe: ServiceProbe::TcpHealth { address },
        });
    }
    if let Some(address) = config.collectors.redis_address {
        targets.push(ServiceTarget {
            name: "redis".to_owned(),
            unit: None,
            cgroup_path: None,
            probe: ServiceProbe::RedisAddress { address },
        });
    }
    targets
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
                            app.storage.note_queue_send_started();
                            if storage_tx.try_send(telemetry).is_err() {
                                app.storage.note_queue_send_failed();
                                control_warn!(
                                    "CONTROL_TRAFFIC_QUEUE_FULL",
                                    "traffic persistence queue full; sample dropped"
                                );
                            }
                        }
                        Err(error) => control_warn!(
                            "CONTROL_TELEMETRY_INVALID",
                            error = %error,
                            "invalid telemetry datagram dropped"
                        ),
                    }
                }
                Err(error) => control_warn!(
                    "CONTROL_TELEMETRY_RECEIVE_FAILED",
                    error = %error,
                    "telemetry receive failed"
                ),
            }
        }
    });
    Ok(())
}

fn spawn_storage_writer(
    storage: Arc<SqliteStore>,
    mut receiver: mpsc::Receiver<TelemetryEnvelope>,
) -> Result<(), std::io::Error> {
    let _handle = std::thread::Builder::new()
        .name("vpsguard-storage".to_owned())
        .spawn(move || storage_writer_loop(storage, &mut receiver))?;
    Ok(())
}

fn storage_writer_loop(
    storage: Arc<SqliteStore>,
    receiver: &mut mpsc::Receiver<TelemetryEnvelope>,
) {
    let mut budget_warning_emitted = false;
    while let Some(telemetry) = receiver.blocking_recv() {
        storage.note_queue_dequeued();
        let mut batch = Vec::with_capacity(STORAGE_BATCH_SIZE);
        batch.push(telemetry);
        std::thread::sleep(STORAGE_BATCH_WAIT);
        while batch.len() < STORAGE_BATCH_SIZE {
            let Ok(telemetry) = receiver.try_recv() else {
                break;
            };
            storage.note_queue_dequeued();
            batch.push(telemetry);
        }
        if let Err(error) = storage.refresh_health() {
            control_warn!(
                "CONTROL_STORAGE_HEALTH_REFRESH_FAILED",
                error = %error,
                "storage health refresh failed"
            );
        }
        if !storage.accepts_traffic_writes() {
            storage.note_write_rejected(batch.len());
            if !budget_warning_emitted {
                control_warn!(
                    "CONTROL_STORAGE_BUDGET_EXCEEDED",
                    samples = batch.len(),
                    "traffic persistence paused by database or disk budget"
                );
                budget_warning_emitted = true;
            }
            continue;
        }
        budget_warning_emitted = false;
        if let Err(error) = storage.record_traffic_batch(&batch) {
            storage.note_write_failure(batch.len());
            control_warn!(
                "CONTROL_TRAFFIC_BATCH_PERSISTENCE_FAILED",
                error = %error,
                samples = batch.len(),
                "traffic batch persistence failed"
            );
        }
    }
}

fn spawn_storage_health(storage: Arc<SqliteStore>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(STORAGE_HEALTH_INTERVAL);
        loop {
            interval.tick().await;
            let storage = Arc::clone(&storage);
            match tokio::task::spawn_blocking(move || storage.refresh_health()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => control_warn!(
                    "CONTROL_STORAGE_HEALTH_REFRESH_FAILED",
                    error = %error,
                    "storage health refresh failed"
                ),
                Err(error) => control_warn!(
                    "CONTROL_STORAGE_HEALTH_TASK_FAILED",
                    error = %error,
                    "storage health task failed"
                ),
            }
        }
    });
}

fn spawn_detection_loop(app: Arc<AppState>, config: &GuardConfig) {
    let enforce = automatic_enforcement_enabled(config);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_policy_refresh = None;
        loop {
            interval.tick().await;
            let activation_pending = provider_activation_pending(&app);
            let manual_hold = app.state.read().await.manual_hold;
            if activation_pending && !manual_hold {
                let _operation = app.policy_operation.lock().await;
                let current = app.state.read().await.clone();
                if let Some(reconciled) =
                    reconcile_provider_activation_state(current, &current_timestamp())
                    && let Some(refreshed) = write_policy_for_mode(&app, reconciled).await
                    && persist_state(&app, &refreshed).await.is_ok()
                {
                    *app.state.write().await = refreshed;
                    last_policy_refresh = Some(Instant::now());
                }
                drop(_operation);
                match run_provider_transaction(&app, false).await {
                    Ok(
                        guard_provider::ProviderStage::Complete
                        | guard_provider::ProviderStage::ProxyDrain,
                    ) => {}
                    Ok(stage) => control_warn!(
                        "CONTROL_PROVIDER_RESUME_INCOMPLETE",
                        operation_id = "automatic-provider-resume",
                        ?stage,
                        "provider activation resume stopped before a durable wait or completion"
                    ),
                    Err(error) if error == "PROVIDER_ACTION_IN_PROGRESS" => {}
                    Err(error) => {
                        control_warn!(
                            "CONTROL_PROVIDER_RESUME_FAILED",
                            operation_id = "automatic-provider-resume",
                            error,
                            "provider activation resume failed"
                        );
                        crate::api::record_provider_failure(
                            &app,
                            "automatic-provider-resume",
                            "emergency_proxy",
                            &error,
                        );
                    }
                }
            }
            let policy_refresh_due =
                enforce && policy_renewal_due(last_policy_refresh, Instant::now());
            let pressure = {
                let snapshot = app.os_snapshot.read().await;
                host_pressure(snapshot.as_ref())
            };
            let input = lock_traffic(&app).take_detection_input(pressure);
            let occurred_at = current_timestamp();
            let current = app.state.read().await.clone();
            let Some(input) = input else {
                if policy_refresh_due {
                    let _operation = app.policy_operation.lock().await;
                    let current = app.state.read().await.clone();
                    if let Some(refreshed) = write_policy_for_mode(&app, current).await
                        && persist_state(&app, &refreshed).await.is_ok()
                    {
                        *app.state.write().await = refreshed;
                        last_policy_refresh = Some(Instant::now());
                    }
                }
                continue;
            };
            let assessment = Detector::assess(&input);
            let distributed_pressure = is_distributed_pressure(&input, &assessment);
            let provider_verified = app.provider.try_lock().ok().is_some_and(|provider| {
                provider
                    .as_ref()
                    .is_some_and(ProviderController::protection_active)
            });
            let mut next = current.clone().transition(&TransitionInput {
                assessment: assessment.clone(),
                distributed_pressure,
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
                    Ok(
                        guard_provider::ProviderStage::Complete
                        | guard_provider::ProviderStage::ProxyDrain,
                    ) => {}
                    Ok(stage) => {
                        control_warn!(
                            "CONTROL_PROVIDER_TRANSACTION_INCOMPLETE",
                            operation_id = "automatic-emergency",
                            ?stage,
                            "provider transaction stopped before completion"
                        );
                        crate::api::record_provider_failure(
                            &app,
                            "automatic-emergency",
                            "emergency_proxy",
                            &format!("INCOMPLETE_STAGE_{stage:?}"),
                        );
                        keep_local_guard(&current, &mut next);
                    }
                    Err(error) => {
                        control_warn!(
                            "CONTROL_PROVIDER_TRANSACTION_UNAVAILABLE",
                            operation_id = "automatic-emergency",
                            error,
                            "automatic provider transaction unavailable"
                        );
                        crate::api::record_provider_failure(
                            &app,
                            "automatic-emergency",
                            "emergency_proxy",
                            &error,
                        );
                        keep_local_guard(&current, &mut next);
                    }
                }
            }
            let commit = detection_commit(&current, &next, policy_refresh_due, enforce);
            if !commit.persist {
                continue;
            }
            let _operation = app.policy_operation.lock().await;
            let mut policy_refreshed = false;
            if commit.refresh_policy {
                let Some(refreshed) = write_policy_for_mode(&app, next).await else {
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
            if commit.emit_transition {
                let event = transition_event(&current, &next, &assessment, occurred_at);
                crate::api::publish_event(&app, event);
            }
        }
    });
}

async fn write_policy_for_mode(app: &AppState, state: GuardState) -> Option<GuardState> {
    match app.protection.write_for_state(state).await {
        Ok(state) => Some(state),
        Err(error) => {
            control_warn!(
                "CONTROL_POLICY_SNAPSHOT_GENERATION_FAILED",
                error = %error,
                "policy snapshot generation failed"
            );
            None
        }
    }
}

fn provider_activation_pending(app: &AppState) -> bool {
    app.provider.try_lock().ok().is_some_and(|provider| {
        provider
            .as_ref()
            .is_some_and(ProviderController::activation_pending)
    })
}

fn reconcile_provider_activation_state(
    mut state: GuardState,
    occurred_at: &str,
) -> Option<GuardState> {
    if matches!(
        state.current_mode,
        GuardMode::EmergencyProxy | GuardMode::RecoveryReady | GuardMode::ManualHold
    ) {
        return None;
    }
    state.current_mode = GuardMode::EmergencyProxy;
    state.last_transition_at = occurred_at.to_owned();
    update_incident(&mut state);
    Some(state)
}

fn automatic_enforcement_enabled(config: &GuardConfig) -> bool {
    config.detection.mode == DetectionMode::Enforce
}

fn is_distributed_pressure(input: &guard_core::DetectionInput, assessment: &Assessment) -> bool {
    assessment.bot_likelihood >= 80 || input.host_pressure.score() >= 80
}

fn policy_renewal_due(last_refresh: Option<Instant>, now: Instant) -> bool {
    last_refresh.is_none_or(|last| now.saturating_duration_since(last) >= POLICY_REFRESH_INTERVAL)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetectionCommit {
    persist: bool,
    refresh_policy: bool,
    emit_transition: bool,
}

fn detection_commit(
    current: &GuardState,
    next: &GuardState,
    policy_refresh_due: bool,
    enforce: bool,
) -> DetectionCommit {
    let mode_changed = current.current_mode != next.current_mode;
    DetectionCommit {
        persist: current != next || policy_refresh_due,
        refresh_policy: enforce && (mode_changed || policy_refresh_due),
        emit_transition: mode_changed,
    }
}

async fn run_provider_transaction(
    app: &Arc<AppState>,
    restore: bool,
) -> Result<guard_provider::ProviderStage, String> {
    let _lease = crate::api::ProviderActionLease::acquire(app)
        .ok_or_else(|| "PROVIDER_ACTION_IN_PROGRESS".to_owned())?;
    let provider = Arc::clone(&app.provider);
    let operation_id = format!("auto-{}", Uuid::new_v4());
    let action_name = if restore {
        "automatic_provider_restore"
    } else {
        "automatic_emergency"
    };
    crate::api::record_provider_started(app, &operation_id, action_name);
    let operation_for_task = operation_id.clone();
    let result = tokio::task::spawn_blocking(move || {
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
    .await
    .map_err(|error| format!("PROVIDER_TASK_FAILED: {error}"))?;
    if let Ok(stage) = result {
        crate::api::record_provider_stage(
            app,
            &operation_id,
            action_name,
            if restore {
                GuardMode::Recovering
            } else {
                GuardMode::EmergencyProxy
            },
            stage,
        );
    }
    result
}

fn keep_local_guard(current: &GuardState, next: &mut GuardState) {
    next.current_mode = GuardMode::LocalGuard;
    next.last_transition_at
        .clone_from(&current.last_transition_at);
}

async fn persist_state(app: &AppState, state: &GuardState) -> Result<(), ()> {
    let store = app.state_store.clone();
    let value = state.clone();
    match tokio::task::spawn_blocking(move || store.write(&value)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            control_warn!(
                "CONTROL_STATE_PERSISTENCE_FAILED",
                error = %error,
                "state persistence failed"
            );
            Err(())
        }
        Err(error) => {
            control_warn!(
                "CONTROL_STATE_PERSISTENCE_TASK_FAILED",
                error = %error,
                "state persistence task failed"
            );
            Err(())
        }
    }
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod tests;

fn update_incident(state: &mut GuardState) {
    if matches!(
        state.current_mode,
        GuardMode::LocalGuard | GuardMode::EmergencyProxy | GuardMode::RecoveryReady
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
    let retention = config.retention.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(STORAGE_RETENTION_INTERVAL);
        loop {
            interval.tick().await;
            let cutoffs = RetentionCutoffs::from_config(&retention, unix_millis());
            let storage = Arc::clone(&storage);
            match tokio::task::spawn_blocking(move || storage.retain(&cutoffs)).await {
                Ok(Ok(_deleted)) => {}
                Ok(Err(error)) => control_warn!(
                    "CONTROL_RETENTION_MAINTENANCE_FAILED",
                    error = %error,
                    "retention maintenance failed"
                ),
                Err(error) => control_warn!(
                    "CONTROL_RETENTION_MAINTENANCE_TASK_FAILED",
                    error = %error,
                    "retention maintenance task failed"
                ),
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
        control_warn!(
            "CONTROL_SHUTDOWN_SIGNAL_FAILED",
            "control shutdown signal handler failed"
        );
    }
}
