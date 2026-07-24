//! `vps-guard-edge` 실행 진입점입니다.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use guard_core::correlation::LOG_SCHEMA_VERSION;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "vps-guard-edge", version, about = "VPSGuard Pingora edge")]
struct Cli {
    /// systemd main process로 worker를 관리합니다.
    #[arg(long, hide = true, conflicts_with = "worker")]
    supervisor: bool,
    /// supervisor가 실행하는 내부 Pingora worker입니다.
    #[arg(long, hide = true, conflicts_with = "supervisor")]
    worker: bool,
    /// 실행 중 worker에서 listener FD를 인계받습니다.
    #[arg(long, hide = true, requires = "worker")]
    upgrade: bool,
    /// 설정과 TLS credential만 검증합니다.
    #[arg(long, hide = true, requires = "worker")]
    test: bool,
    /// Certbot hook이 원자 준비한 runtime TLS bundle을 사용합니다.
    #[arg(long, hide = true, requires = "worker")]
    tls_reload: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
        component = "guard-edge",
        event_code = "EDGE_STARTING",
        version = env!("CARGO_PKG_VERSION"),
        build_commit = option_env!("VPS_GUARD_BUILD_COMMIT").unwrap_or("unknown"),
        "edge starting"
    );
    let result = if cli.supervisor {
        guard_edge::run_supervisor(&config_path).map_err(|error| error.to_string())
    } else if cli.worker {
        guard_edge::run_worker_from_path(
            &config_path,
            guard_edge::EdgeWorkerOptions {
                upgrade: cli.upgrade,
                test: cli.test,
                tls_reload: cli.tls_reload,
            },
        )
        .map_err(|error| error.to_string())
    } else {
        guard_edge::run_from_path(&config_path).map_err(|error| error.to_string())
    };
    match result {
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
