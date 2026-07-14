//! 검증된 core 설정을 hot path 친화적인 runtime 값으로 변환합니다.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use guard_core::config::{GuardConfig, OriginProtocol};
use ipnet::IpNet;
use thiserror::Error;

use crate::policy::path_matches_any;
use crate::rate_limit::RouteClass;

/// 한 TLS listener에 적용할 PEM 경로입니다.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeTlsConfig {
    pub(crate) listen_addr: String,
    pub(crate) cert_file: PathBuf,
    pub(crate) key_file: PathBuf,
}

/// `guard-edge`가 요청마다 참조하는 불변 runtime 설정입니다.
#[derive(Debug, Clone)]
pub(crate) struct EdgeRuntimeConfig {
    pub(crate) listen_addr: String,
    pub(crate) tls: Option<RuntimeTlsConfig>,
    pub(crate) origin_host: String,
    pub(crate) origin_port: u16,
    pub(crate) origin_tls: bool,
    pub(crate) origin_sni: String,
    pub(crate) allowed_hosts: Vec<String>,
    pub(crate) canonical_host: Option<String>,
    pub(crate) trusted_proxy_cidrs: Vec<IpNet>,
    pub(crate) max_body_bytes: u64,
    pub(crate) upload_max_body_bytes: u64,
    pub(crate) upload_path_prefixes: Vec<String>,
    pub(crate) strict_path_prefixes: Vec<String>,
    pub(crate) upstream_connect_timeout: Duration,
    pub(crate) upstream_read_timeout: Duration,
    pub(crate) upload_upstream_read_timeout: Duration,
    pub(crate) max_tracked_clients: usize,
    pub(crate) rate_limit_rpm: Option<u32>,
    pub(crate) strict_rate_limit_rpm: Option<u32>,
    pub(crate) upload_rate_limit_rpm: Option<u32>,
    pub(crate) telemetry_socket: PathBuf,
}

/// core 설정은 유효하지만 현재 edge runtime이 지원하지 못하는 조합입니다.
#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    /// TLS origin에는 명시적 SNI가 필요합니다.
    #[error("HTTPS origin에는 origin.sni가 필요합니다")]
    MissingOriginSni,
    /// multi-SNI listener는 후속 TLS batch에서 적용합니다.
    #[error("현재 listener는 인증서 한 개만 지원합니다: count={0}")]
    MultipleCertificates(usize),
}

impl EdgeRuntimeConfig {
    pub(crate) fn try_from_guard(config: &GuardConfig) -> Result<Self, RuntimeConfigError> {
        let origin_tls = config.origin.protocol == OriginProtocol::Https;
        let origin_sni = match (&config.origin.sni, origin_tls) {
            (Some(sni), _) => sni.clone(),
            (None, false) => String::new(),
            (None, true) => return Err(RuntimeConfigError::MissingOriginSni),
        };
        let tls = match config.edge.https_bind {
            None => None,
            Some(listen_addr) => {
                if config.tls.certificates.len() != 1 {
                    return Err(RuntimeConfigError::MultipleCertificates(
                        config.tls.certificates.len(),
                    ));
                }
                let certificate = &config.tls.certificates[0];
                Some(RuntimeTlsConfig {
                    listen_addr: listen_addr.to_string(),
                    cert_file: certificate.cert_file.clone(),
                    key_file: certificate.key_file.clone(),
                })
            }
        };
        Ok(Self {
            listen_addr: config.edge.http_bind.to_string(),
            tls,
            origin_host: config.origin.address.ip().to_string(),
            origin_port: config.origin.address.port(),
            origin_tls,
            origin_sni,
            allowed_hosts: config.edge.allowed_hosts.clone(),
            canonical_host: config.edge.canonical_host.clone(),
            trusted_proxy_cidrs: config.edge.trusted_proxy_cidrs.clone(),
            max_body_bytes: config.edge.max_body_bytes,
            upload_max_body_bytes: config.edge.upload_max_body_bytes,
            upload_path_prefixes: config.edge.upload_path_prefixes.clone(),
            strict_path_prefixes: config.edge.strict_path_prefixes.clone(),
            upstream_connect_timeout: Duration::from_millis(
                config.edge.upstream_connect_timeout_ms,
            ),
            upstream_read_timeout: Duration::from_millis(config.edge.upstream_read_timeout_ms),
            upload_upstream_read_timeout: Duration::from_millis(
                config.edge.upload_upstream_read_timeout_ms,
            ),
            max_tracked_clients: config.edge.max_tracked_clients,
            rate_limit_rpm: config.edge.rate_limit_rpm,
            strict_rate_limit_rpm: config.edge.strict_rate_limit_rpm,
            upload_rate_limit_rpm: config.edge.upload_rate_limit_rpm,
            telemetry_socket: config.edge.telemetry_socket.clone(),
        })
    }

    pub(crate) fn route_class(&self, path: &str) -> RouteClass {
        if path_matches_any(path, &self.upload_path_prefixes) {
            RouteClass::Upload
        } else if path_matches_any(path, &self.strict_path_prefixes) {
            RouteClass::Strict
        } else {
            RouteClass::General
        }
    }

    pub(crate) fn body_limit(&self, route_class: RouteClass) -> u64 {
        if route_class == RouteClass::Upload {
            self.upload_max_body_bytes
        } else {
            self.max_body_bytes
        }
    }

    pub(crate) fn rate_limit(&self, route_class: RouteClass) -> Option<u32> {
        match route_class {
            RouteClass::General => self.rate_limit_rpm,
            RouteClass::Strict => self.strict_rate_limit_rpm.or(self.rate_limit_rpm),
            RouteClass::Upload => self.upload_rate_limit_rpm.or(self.rate_limit_rpm),
        }
    }

    pub(crate) fn trusts_peer(&self, peer: IpAddr) -> bool {
        self.trusted_proxy_cidrs
            .iter()
            .any(|network| network.contains(&peer))
    }
}
