//! 설정을 읽고 Pingora listener를 기동하는 startup orchestration입니다.

use std::fs;
use std::path::Path;

use guard_core::{ConfigError, GuardConfig};
use pingora_core::server::Server;
use pingora_core::server::configuration::Opt;
use pingora_proxy::http_proxy_service;
use thiserror::Error;
use tracing::info;

use crate::proxy::GuardEdge;
use crate::runtime::{EdgeRuntimeConfig, RuntimeConfigError};

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
    /// Pingora server를 만들지 못했습니다.
    #[error("Pingora server 초기화 실패: {0}")]
    Server(String),
    /// TLS listener를 추가하지 못했습니다.
    #[error("TLS listener 초기화 실패: {0}")]
    TlsListener(String),
}

/// TOML 설정을 읽고 검증한 뒤 edge server를 실행합니다.
///
/// # Errors
///
/// 파일, 설정, crypto provider 또는 listener 초기화가 실패하면 반환합니다.
pub fn run_from_path(path: &Path) -> Result<(), EdgeStartupError> {
    let source = fs::read_to_string(path)?;
    let config = GuardConfig::from_toml(&source)?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;
    install_crypto_provider()?;
    run_server(runtime)
}

fn install_crypto_provider() -> Result<(), EdgeStartupError> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| EdgeStartupError::CryptoProvider)
}

fn run_server(runtime: EdgeRuntimeConfig) -> Result<(), EdgeStartupError> {
    let options = Opt::parse_args();
    let mut server = Server::new(Some(options))
        .map_err(|error| EdgeStartupError::Server(format!("{error:?}")))?;
    server.bootstrap();
    let app = GuardEdge::new(runtime.clone());
    let mut service = http_proxy_service(&server.configuration, app);
    service.add_tcp(&runtime.listen_addr);
    if let Some(tls) = &runtime.tls {
        service
            .add_tls(
                &tls.listen_addr,
                tls.cert_file.to_string_lossy().as_ref(),
                tls.key_file.to_string_lossy().as_ref(),
            )
            .map_err(|error| EdgeStartupError::TlsListener(format!("{error:?}")))?;
    }
    info!(
        http_listener = %runtime.listen_addr,
        tls_listener = ?runtime.tls.as_ref().map(|tls| tls.listen_addr.as_str()),
        origin_host = %runtime.origin_host,
        origin_port = runtime.origin_port,
        "starting guard edge"
    );
    server.add_service(service);
    server.run_forever();
}
