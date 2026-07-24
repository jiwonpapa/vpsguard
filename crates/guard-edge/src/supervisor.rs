//! systemd main process를 유지하며 Pingora worker를 무중단 교체합니다.
//!
//! supervisor는 요청을 처리하지 않습니다. reload 때 새 worker를 사전검증한 뒤
//! Pingora의 Linux listener FD handoff를 사용하고 기존 worker는 연결을 drain합니다.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};
use signal_hook::consts::signal::{SIGCHLD, SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use thiserror::Error;
use tracing::{error, info, warn};

const UPGRADE_SOCKET: &str = "/run/vps-guard/pingora-upgrade.sock";
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(12);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// worker 사전검증·spawn·signal·FD 인계 실패입니다.
#[derive(Debug, Error)]
pub enum EdgeSupervisorError {
    /// Linux listener FD handoff를 지원하지 않는 OS입니다.
    #[error("VPSGuard edge supervisor는 Linux에서만 지원됩니다")]
    UnsupportedPlatform,
    /// 현재 실행 파일을 찾지 못했습니다.
    #[error("edge 실행 파일 경로 확인 실패: {0}")]
    CurrentExecutable(#[source] std::io::Error),
    /// Unix signal 수신기를 만들지 못했습니다.
    #[error("edge supervisor signal 초기화 실패: {0}")]
    Signals(#[source] std::io::Error),
    /// worker process를 시작하지 못했습니다.
    #[error("edge worker 시작 실패: phase={phase}, cause={source}")]
    Spawn {
        /// preflight, initial 또는 upgrade입니다.
        phase: &'static str,
        /// process spawn 오류입니다.
        source: std::io::Error,
    },
    /// worker process 상태를 읽지 못했습니다.
    #[error("edge worker 상태 확인 실패: {0}")]
    Wait(#[source] std::io::Error),
    /// worker 사전검증이 실패했습니다.
    #[error("edge worker 사전검증 실패: status={0}")]
    PreflightFailed(ExitStatus),
    /// 현재 worker가 예기치 않게 종료됐습니다.
    #[error("현재 edge worker가 종료됐습니다: status={0}")]
    WorkerExited(ExitStatus),
    /// reload bundle 파일 또는 권한이 안전하지 않습니다.
    #[error("TLS reload bundle이 없거나 안전하지 않습니다")]
    UnsafeReloadBundle,
    /// 이전 worker가 drain 중이라 중복 reload를 거부했습니다.
    #[error("이전 edge worker가 drain 중이므로 reload를 재시도해야 합니다")]
    ReloadInProgress,
    /// child PID를 OS PID로 변환하지 못했습니다.
    #[error("edge worker PID 범위를 벗어났습니다")]
    InvalidPid,
    /// worker에 signal을 보내지 못했습니다.
    #[error("edge worker signal 실패: signal={signal}, cause={source}")]
    Signal {
        /// 전송하려던 signal입니다.
        signal: &'static str,
        /// OS 오류입니다.
        source: rustix::io::Errno,
    },
    /// 새 worker의 upgrade socket 준비가 시간 안에 끝나지 않았습니다.
    #[error("새 edge worker의 upgrade socket 준비 시간 초과")]
    UpgradeSocketTimeout,
    /// Pingora listener FD 인계가 시간 안에 끝나지 않았습니다.
    #[error("Pingora listener FD 인계 시간 초과")]
    TransferTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerLaunch {
    Preflight { tls_reload: bool },
    Initial,
    Upgrade,
}

impl WorkerLaunch {
    const fn phase(self) -> &'static str {
        match self {
            Self::Preflight { .. } => "preflight",
            Self::Initial => "initial",
            Self::Upgrade => "upgrade",
        }
    }

    fn arguments(self) -> Vec<OsString> {
        let mut arguments = vec![OsString::from("--worker")];
        match self {
            Self::Preflight { tls_reload } => {
                arguments.push(OsString::from("--test"));
                if tls_reload {
                    arguments.push(OsString::from("--tls-reload"));
                }
            }
            Self::Initial => {}
            Self::Upgrade => {
                arguments.push(OsString::from("--upgrade"));
                arguments.push(OsString::from("--tls-reload"));
            }
        }
        arguments
    }
}

struct EdgeSupervisor {
    executable: PathBuf,
    config_path: PathBuf,
    current: Child,
    draining: Vec<Child>,
}

impl EdgeSupervisor {
    fn start(executable: PathBuf, config_path: PathBuf) -> Result<Self, EdgeSupervisorError> {
        run_preflight(&executable, &config_path, false)?;
        let current = spawn_worker(&executable, &config_path, WorkerLaunch::Initial)?;
        Ok(Self {
            executable,
            config_path,
            current,
            draining: Vec::new(),
        })
    }

    fn reload(&mut self) -> Result<(), EdgeSupervisorError> {
        self.reap_draining()?;
        if !self.draining.is_empty() {
            return Err(EdgeSupervisorError::ReloadInProgress);
        }
        validate_reload_bundle()?;
        run_preflight(&self.executable, &self.config_path, true)?;
        let mut next = spawn_worker(&self.executable, &self.config_path, WorkerLaunch::Upgrade)?;
        if let Err(error) = wait_for_upgrade_socket(&mut next) {
            let _ = signal_child(&next, Signal::INT, "SIGINT");
            return Err(error);
        }
        signal_child(&self.current, Signal::QUIT, "SIGQUIT")?;
        wait_for_fd_transfer(&mut next)?;
        let previous = std::mem::replace(&mut self.current, next);
        self.draining.push(previous);
        info!(
            component = "guard-edge",
            event_code = "EDGE_GRACEFUL_RELOAD_STARTED",
            current_worker_pid = self.current.id(),
            draining_workers = self.draining.len(),
            "edge worker accepted Pingora listener handoff"
        );
        Ok(())
    }

    fn child_event(&mut self) -> Result<(), EdgeSupervisorError> {
        if let Some(status) = self.current.try_wait().map_err(EdgeSupervisorError::Wait)? {
            return Err(EdgeSupervisorError::WorkerExited(status));
        }
        self.reap_draining()
    }

    fn reap_draining(&mut self) -> Result<(), EdgeSupervisorError> {
        let mut active = Vec::with_capacity(self.draining.len());
        for mut worker in self.draining.drain(..) {
            match worker.try_wait().map_err(EdgeSupervisorError::Wait)? {
                Some(status) => {
                    info!(
                        component = "guard-edge",
                        event_code = "EDGE_DRAINED_WORKER_EXITED",
                        worker_pid = worker.id(),
                        %status,
                        "drained edge worker exited"
                    );
                }
                None => active.push(worker),
            }
        }
        self.draining = active;
        Ok(())
    }

    fn shutdown(&mut self, signal: Signal, name: &'static str) {
        for worker in self.draining.iter().chain(std::iter::once(&self.current)) {
            if let Err(signal_error) = signal_child(worker, signal, name) {
                warn!(
                    component = "guard-edge",
                    event_code = "EDGE_WORKER_SHUTDOWN_SIGNAL_FAILED",
                    error = %signal_error,
                    worker_pid = worker.id(),
                    "edge worker shutdown signal failed"
                );
            }
        }
    }
}

/// systemd가 추적하는 supervisor를 실행하고 child Pingora worker를 관리합니다.
///
/// # Errors
///
/// worker 사전검증·spawn·signal·FD 인계 또는 signal 수신기 초기화 실패를
/// 반환합니다.
pub fn run_supervisor(config_path: &Path) -> Result<(), EdgeSupervisorError> {
    if !cfg!(target_os = "linux") {
        return Err(EdgeSupervisorError::UnsupportedPlatform);
    }
    let executable = std::env::current_exe().map_err(EdgeSupervisorError::CurrentExecutable)?;
    let mut signals =
        Signals::new([SIGHUP, SIGTERM, SIGINT, SIGCHLD]).map_err(EdgeSupervisorError::Signals)?;
    let mut supervisor = EdgeSupervisor::start(executable, config_path.to_path_buf())?;
    info!(
        component = "guard-edge",
        event_code = "EDGE_SUPERVISOR_STARTED",
        worker_pid = supervisor.current.id(),
        "edge supervisor started"
    );
    for signal in signals.forever() {
        match signal {
            SIGHUP => {
                if let Err(reload_error) = supervisor.reload() {
                    error!(
                        component = "guard-edge",
                        error_code = "EDGE_GRACEFUL_RELOAD_FAILED",
                        error = %reload_error,
                        "edge graceful reload rejected"
                    );
                }
            }
            SIGCHLD => supervisor.child_event()?,
            SIGTERM => {
                supervisor.shutdown(Signal::TERM, "SIGTERM");
                return Ok(());
            }
            SIGINT => {
                supervisor.shutdown(Signal::INT, "SIGINT");
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}

fn run_preflight(
    executable: &Path,
    config_path: &Path,
    tls_reload: bool,
) -> Result<(), EdgeSupervisorError> {
    let mut worker = spawn_worker(
        executable,
        config_path,
        WorkerLaunch::Preflight { tls_reload },
    )?;
    let status = worker.wait().map_err(EdgeSupervisorError::Wait)?;
    if !status.success() {
        return Err(EdgeSupervisorError::PreflightFailed(status));
    }
    Ok(())
}

fn spawn_worker(
    executable: &Path,
    config_path: &Path,
    launch: WorkerLaunch,
) -> Result<Child, EdgeSupervisorError> {
    Command::new(executable)
        .args(launch.arguments())
        .env("VPS_GUARD_CONFIG", config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|source| EdgeSupervisorError::Spawn {
            phase: launch.phase(),
            source,
        })
}

fn validate_reload_bundle() -> Result<(), EdgeSupervisorError> {
    for path in [
        Path::new("/run/vps-guard-tls"),
        Path::new(guard_system::VPS_GUARD_TLS_RELOAD_DIRECTORY),
    ] {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| EdgeSupervisorError::UnsafeReloadBundle)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o777 != 0o750
        {
            return Err(EdgeSupervisorError::UnsafeReloadBundle);
        }
    }
    for path in [
        guard_system::VPS_GUARD_TLS_RELOAD_CERTIFICATE,
        guard_system::VPS_GUARD_TLS_RELOAD_KEY,
    ] {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| EdgeSupervisorError::UnsafeReloadBundle)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o777 != 0o440
        {
            return Err(EdgeSupervisorError::UnsafeReloadBundle);
        }
    }
    Ok(())
}

fn wait_for_upgrade_socket(next: &mut Child) -> Result<(), EdgeSupervisorError> {
    let started = Instant::now();
    while started.elapsed() < SOCKET_READY_TIMEOUT {
        if let Some(status) = next.try_wait().map_err(EdgeSupervisorError::Wait)? {
            return Err(EdgeSupervisorError::WorkerExited(status));
        }
        if Path::new(UPGRADE_SOCKET).exists() {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(EdgeSupervisorError::UpgradeSocketTimeout)
}

fn wait_for_fd_transfer(next: &mut Child) -> Result<(), EdgeSupervisorError> {
    let started = Instant::now();
    while started.elapsed() < TRANSFER_TIMEOUT {
        if let Some(status) = next.try_wait().map_err(EdgeSupervisorError::Wait)? {
            return Err(EdgeSupervisorError::WorkerExited(status));
        }
        if !Path::new(UPGRADE_SOCKET).exists() {
            thread::sleep(Duration::from_millis(250));
            if let Some(status) = next.try_wait().map_err(EdgeSupervisorError::Wait)? {
                return Err(EdgeSupervisorError::WorkerExited(status));
            }
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
    Err(EdgeSupervisorError::TransferTimeout)
}

fn signal_child(
    child: &Child,
    signal: Signal,
    name: &'static str,
) -> Result<(), EdgeSupervisorError> {
    let raw = i32::try_from(child.id()).map_err(|_| EdgeSupervisorError::InvalidPid)?;
    let pid = Pid::from_raw(raw).ok_or(EdgeSupervisorError::InvalidPid)?;
    kill_process(pid, signal).map_err(|source| EdgeSupervisorError::Signal {
        signal: name,
        source,
    })
}

#[cfg(test)]
#[path = "supervisor/tests.rs"]
mod tests;
