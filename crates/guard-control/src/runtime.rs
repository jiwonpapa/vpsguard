//! control 설정, telemetry receiver와 loopback API startup을 조율합니다.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use guard_agent::os;
use guard_core::{ConfigError, GuardConfig, GuardState};
use guard_system::{AtomicJsonStore, StoreError};
use thiserror::Error;
use tokio::net::{TcpListener, UnixDatagram};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::api::{AppState, router};
use crate::telemetry::{TelemetryEnvelope, TrafficAggregator};

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
    let app = Arc::new(AppState {
        state: RwLock::new(initial_state),
        state_store: store,
        traffic: Mutex::new(TrafficAggregator::new(config.edge.max_tracked_clients)),
        os_snapshot: RwLock::new(None),
        action_token: std::env::var("VPS_GUARD_ACTION_TOKEN").unwrap_or_default(),
        completed_actions: Mutex::new(VecDeque::with_capacity(1_024)),
    });
    spawn_os_collector(Arc::clone(&app));
    spawn_telemetry_receiver(Arc::clone(&app), config.edge.telemetry_socket.clone())?;
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

fn spawn_telemetry_receiver(app: Arc<AppState>, path: PathBuf) -> Result<(), ControlError> {
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
                        Ok(telemetry) => lock_traffic(&app).ingest(&telemetry),
                        Err(error) => warn!(error = %error, "invalid telemetry datagram dropped"),
                    }
                }
                Err(error) => warn!(error = %error, "telemetry receive failed"),
            }
        }
    });
    Ok(())
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
