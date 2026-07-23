//! Standalone 설치의 PAM·UFW 최소 권한 helper 진입점입니다.

use std::path::PathBuf;
use std::process::ExitCode;

use guard_core::correlation::LOG_SCHEMA_VERSION;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
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
    info!(
        log_schema_version = LOG_SCHEMA_VERSION,
        component = "guard-privileged",
        event_code = "PRIVILEGED_STARTING",
        version = env!("CARGO_PKG_VERSION"),
        build_commit = option_env!("VPS_GUARD_BUILD_COMMIT").unwrap_or("unknown"),
        "privileged helper starting"
    );
    match guard_control::run_privileged_from_path(&config_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(
                log_schema_version = LOG_SCHEMA_VERSION,
                component = "guard-privileged",
                error_code = "PRIVILEGED_STARTUP_FAILED",
                error = %error,
                path = %config_path.display(),
                "privileged helper startup failed"
            );
            ExitCode::FAILURE
        }
    }
}
