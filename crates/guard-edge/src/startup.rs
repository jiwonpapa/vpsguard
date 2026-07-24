//! 설정을 읽고 Pingora listener를 기동하는 startup orchestration입니다.

use std::fs;
use std::path::Path;

use guard_core::correlation::LOG_SCHEMA_VERSION;
use guard_core::{ConfigError, GuardConfig};
use pingora_core::apps::HttpServerOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::{Opt, ServerConf};
use pingora_proxy::ProxyServiceBuilder;
use thiserror::Error;
use tracing::info;

use crate::proxy::GuardEdge;
use crate::runtime::{EdgeRuntimeConfig, RuntimeConfigError};
use crate::tls::{TlsPreflightError, preflight};

const UPGRADE_SOCKET: &str = "/run/vps-guard/pingora-upgrade.sock";
const GRACE_PERIOD_SECONDS: u64 = 30;
const GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = 5;

#[cfg(test)]
#[path = "startup/tests.rs"]
mod tests;

/// 내부 Pingora worker의 실행 모드입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdgeWorkerOptions {
    /// 실행 중 worker에서 listener FD를 인계받습니다.
    pub upgrade: bool,
    /// 설정과 TLS credential만 검증하고 listener를 열지 않습니다.
    pub test: bool,
    /// Certbot hook이 준비한 runtime TLS bundle을 사용합니다.
    pub tls_reload: bool,
}

/// Edge가 listener를 열기 전 발생할 수 있는 startup 실패입니다.
#[derive(Debug, Error)]
pub enum EdgeStartupError {
    /// 설정 파일을 읽을 수 없습니다.
    #[error("설정 파일을 읽지 못했습니다: {0}")]
    ReadConfig(#[from] std::io::Error),
    /// 설정 계약 검증에 실패했습니다.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// 설정은 유효하지만 현재 runtime 기능 범위를 벗어납니다.
    #[error(transparent)]
    Runtime(#[from] RuntimeConfigError),
    /// rustls provider를 설치하지 못했습니다.
    #[error("rustls crypto provider를 설치하지 못했습니다")]
    CryptoProvider,
    /// TLS listener를 추가하지 못했습니다.
    #[error("TLS listener 초기화 실패: {0}")]
    TlsListener(String),
    /// 인증서, key, domain 또는 유효기간 사전 검증 실패입니다.
    #[error(transparent)]
    TlsPreflight(#[from] TlsPreflightError),
    /// TLS listener 없이 reload bundle 사용이 요청됐습니다.
    #[error("TLS listener가 없으므로 reload bundle을 사용할 수 없습니다")]
    TlsReloadWithoutListener,
}

/// TOML 설정을 읽고 검증한 뒤 edge server를 실행합니다.
///
/// # Errors
///
/// 파일, 설정, crypto provider 또는 listener 초기화가 실패하면 반환합니다.
pub fn run_from_path(path: &Path) -> Result<(), EdgeStartupError> {
    run_worker_from_path(path, EdgeWorkerOptions::default())
}

/// TOML 설정을 읽고 내부 worker 옵션에 따라 edge server를 실행합니다.
///
/// # Errors
///
/// 파일, 설정, crypto provider, TLS reload bundle 또는 listener 초기화가 실패하면
/// 반환합니다.
pub fn run_worker_from_path(
    path: &Path,
    options: EdgeWorkerOptions,
) -> Result<(), EdgeStartupError> {
    let mut runtime = load_runtime(path)?;
    if options.tls_reload {
        let tls = runtime
            .tls
            .as_mut()
            .ok_or(EdgeStartupError::TlsReloadWithoutListener)?;
        tls.cert_file = guard_system::VPS_GUARD_TLS_RELOAD_CERTIFICATE.into();
        tls.key_file = guard_system::VPS_GUARD_TLS_RELOAD_KEY.into();
    }
    install_crypto_provider()?;
    if let Some(tls) = &runtime.tls {
        preflight(tls)?;
    }
    run_server(runtime, options)
}

fn load_runtime(path: &Path) -> Result<EdgeRuntimeConfig, EdgeStartupError> {
    let source = fs::read_to_string(path)?;
    let config = GuardConfig::from_toml(&source)?;
    Ok(EdgeRuntimeConfig::try_from_guard(&config)?)
}

fn install_crypto_provider() -> Result<(), EdgeStartupError> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| EdgeStartupError::CryptoProvider)
}

fn run_server(
    runtime: EdgeRuntimeConfig,
    worker_options: EdgeWorkerOptions,
) -> Result<(), EdgeStartupError> {
    let options = Opt {
        upgrade: worker_options.upgrade,
        daemon: false,
        nocapture: false,
        test: worker_options.test,
        conf: None,
    };
    let configuration = server_configuration();
    let mut server = Server::new_with_opt_and_conf(Some(options), configuration);
    server.bootstrap();
    let app = GuardEdge::new(runtime.clone());
    let mut server_options = HttpServerOptions::default();
    server_options.keepalive_request_limit = Some(runtime.keepalive_request_limit);
    let mut service = ProxyServiceBuilder::new(&server.configuration, app)
        .server_options(server_options)
        .build();
    service.add_tcp(&runtime.listen_addr);
    if let Some(tls) = &runtime.tls {
        let mut settings = TlsSettings::intermediate(
            tls.cert_file.to_string_lossy().as_ref(),
            tls.key_file.to_string_lossy().as_ref(),
        )
        .map_err(|error| EdgeStartupError::TlsListener(format!("{error:?}")))?;
        settings.enable_h2();
        service.add_tls_with_settings(&tls.listen_addr, None, settings);
    }
    info!(
        log_schema_version = LOG_SCHEMA_VERSION,
        component = "guard-edge",
        event_code = "EDGE_STARTED",
        http_listener = %runtime.listen_addr,
        tls_listener = ?runtime.tls.as_ref().map(|tls| tls.listen_addr.as_str()),
        origin_host = %runtime.origin_host,
        origin_port = runtime.origin_port,
        "starting guard edge"
    );
    server.add_service(service);
    server.run_forever();
}

fn server_configuration() -> ServerConf {
    ServerConf {
        upgrade_sock: UPGRADE_SOCKET.to_owned(),
        grace_period_seconds: Some(GRACE_PERIOD_SECONDS),
        graceful_shutdown_timeout_seconds: Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS),
        upgrade_sock_connect_accept_max_retries: Some(10),
        ..ServerConf::default()
    }
}
