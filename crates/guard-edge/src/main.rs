//! `vps-guard-edge` 실행 진입점입니다.

use std::path::PathBuf;
use std::process::ExitCode;

use guard_core::correlation::LOG_SCHEMA_VERSION;
use tracing::error;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    if let Err(initialization_error) = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .try_init()
    {
        eprintln!("VPSGuard 로그 초기화 실패: {initialization_error}");
        return ExitCode::FAILURE;
    }

    let config_path = std::env::var_os("VPS_GUARD_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/vps-guard/config.toml"));
    match guard_edge::run_from_path(&config_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(startup_error) => {
            error!(
                log_schema_version = LOG_SCHEMA_VERSION,
                component = "guard-edge",
                error_code = "EDGE_STARTUP_FAILED",
                error = %startup_error,
                path = %config_path.display(),
                "edge startup failed"
            );
            ExitCode::FAILURE
        }
    }
}
