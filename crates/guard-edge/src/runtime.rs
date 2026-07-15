//! 검증된 core 설정을 hot path 친화적인 runtime 값으로 변환합니다.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use guard_core::config::{
    DetectionMode, DetectionProfile, GuardConfig, InspectionMode, OriginProtocol,
};
use guard_profiles::{ApplicationProfile, RouteKind, classify};
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
    pub(crate) domains: Vec<String>,
}

/// 관리 Host가 선택됐을 때만 사용하는 loopback Control upstream입니다.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeManagementConfig {
    pub(crate) host: String,
    pub(crate) origin_host: String,
    pub(crate) origin_port: u16,
    pub(crate) login_rate_limit_rpm: u32,
}

/// request가 절대로 섞이면 안 되는 upstream 경계입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamKind {
    /// 사용자 애플리케이션 origin입니다.
    Application,
    /// VPSGuard loopback Control입니다.
    Management,
}

/// 최종 route class가 선택된 typed 계층입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteClassSource {
    /// 일반 core 안전 한도만 적용됐습니다.
    CoreDefault,
    /// 애플리케이션 profile이 class를 강화했습니다.
    ApplicationProfile,
    /// 명시적 site strict prefix가 우선했습니다.
    SiteStrictOverride,
    /// 명시적 site upload prefix가 우선했습니다.
    SiteUploadOverride,
    /// 관리 session endpoint 전용 class입니다.
    ManagementAuth,
}

/// 정적·app·site 계층을 합성한 request profile입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveRouteProfile {
    pub(crate) route_class: RouteClass,
    pub(crate) normalized_route: String,
    pub(crate) base_cost: u8,
    pub(crate) source: RouteClassSource,
}

/// `guard-edge`가 요청마다 참조하는 불변 runtime 설정입니다.
#[derive(Debug, Clone)]
pub(crate) struct EdgeRuntimeConfig {
    pub(crate) listen_addr: String,
    pub(crate) tls: Option<RuntimeTlsConfig>,
    pub(crate) management: Option<RuntimeManagementConfig>,
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
    pub(crate) policy_path: PathBuf,
    pub(crate) policy_reload_interval: Duration,
    pub(crate) challenge_secret_file: Option<PathBuf>,
    pub(crate) clearance_ttl_seconds: u64,
    pub(crate) application_profile: ApplicationProfile,
    pub(crate) inspection_mode: InspectionMode,
    pub(crate) detection_mode: DetectionMode,
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
    /// systemd TLS credential 경로를 해석하지 못했습니다.
    #[error(transparent)]
    TlsCredential(#[from] guard_system::tls::CertificateValidationError),
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
                    cert_file: guard_system::resolve_tls_credential_path(&certificate.cert_file)?,
                    key_file: guard_system::resolve_tls_credential_path(&certificate.key_file)?,
                    domains: certificate.domains.clone(),
                })
            }
        };
        let management = config
            .ui
            .public_host
            .as_ref()
            .map(|host| RuntimeManagementConfig {
                host: host.to_ascii_lowercase(),
                origin_host: config.ui.bind.ip().to_string(),
                origin_port: config.ui.bind.port(),
                login_rate_limit_rpm: config.ui.login_rate_limit_rpm,
            });
        let mut allowed_hosts = config.edge.allowed_hosts.clone();
        if let Some(management) = &management {
            allowed_hosts.push(management.host.clone());
        }
        Ok(Self {
            listen_addr: config.edge.http_bind.to_string(),
            tls,
            management,
            origin_host: config.origin.address.ip().to_string(),
            origin_port: config.origin.address.port(),
            origin_tls,
            origin_sni,
            allowed_hosts,
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
            policy_path: config.edge.policy_path.clone(),
            policy_reload_interval: Duration::from_millis(config.edge.policy_reload_interval_ms),
            challenge_secret_file: config.edge.challenge_secret_file.clone(),
            clearance_ttl_seconds: config.edge.clearance_ttl_seconds,
            application_profile: match config.detection.profile {
                DetectionProfile::Php => ApplicationProfile::Php,
                DetectionProfile::Gnuboard5 => ApplicationProfile::Gnuboard5,
                DetectionProfile::Gnuboard7 => ApplicationProfile::Gnuboard7,
                DetectionProfile::Wordpress => ApplicationProfile::Wordpress,
            },
            inspection_mode: config.detection.inspection,
            detection_mode: config.detection.mode,
        })
    }

    /// Host를 정규화해 별도 관리 upstream인지 결정합니다.
    pub(crate) fn upstream_kind(&self, host: Option<&str>) -> UpstreamKind {
        let is_management = self.management.as_ref().is_some_and(|management| {
            host.is_some_and(|value| {
                crate::policy::normalize_host(value).eq_ignore_ascii_case(&management.host)
            })
        });
        if is_management {
            UpstreamKind::Management
        } else {
            UpstreamKind::Application
        }
    }

    /// core 안전 한도, app profile과 site override를 한 번에 합성합니다.
    pub(crate) fn effective_route_profile(
        &self,
        upstream: UpstreamKind,
        path: &str,
        target: &str,
    ) -> EffectiveRouteProfile {
        if upstream == UpstreamKind::Management {
            let management_auth = path == "/api/v1/session";
            return EffectiveRouteProfile {
                route_class: if management_auth {
                    RouteClass::ManagementAuth
                } else {
                    RouteClass::General
                },
                normalized_route: path.to_owned(),
                base_cost: if management_auth { 12 } else { 2 },
                source: if management_auth {
                    RouteClassSource::ManagementAuth
                } else {
                    RouteClassSource::CoreDefault
                },
            };
        }
        let site_override = if path_matches_any(path, &self.upload_path_prefixes) {
            (RouteClass::Upload, RouteClassSource::SiteUploadOverride)
        } else if path_matches_any(path, &self.strict_path_prefixes) {
            (RouteClass::Strict, RouteClassSource::SiteStrictOverride)
        } else {
            (RouteClass::General, RouteClassSource::CoreDefault)
        };
        if self.inspection_mode == InspectionMode::ProtocolOnly {
            return EffectiveRouteProfile {
                route_class: site_override.0,
                normalized_route: path.to_owned(),
                base_cost: 1,
                source: site_override.1,
            };
        }
        let application = classify(self.application_profile, target);
        let (route_class, source) = if site_override.1 != RouteClassSource::CoreDefault {
            site_override
        } else {
            match application.kind {
                RouteKind::Upload => (RouteClass::Upload, RouteClassSource::ApplicationProfile),
                RouteKind::Admin
                | RouteKind::Authentication
                | RouteKind::Search
                | RouteKind::Write
                | RouteKind::RemoteProcedure => {
                    (RouteClass::Strict, RouteClassSource::ApplicationProfile)
                }
                RouteKind::Static
                | RouteKind::Public
                | RouteKind::Board
                | RouteKind::Media
                | RouteKind::Dynamic
                | RouteKind::Api => (RouteClass::General, RouteClassSource::CoreDefault),
            }
        };
        EffectiveRouteProfile {
            route_class,
            normalized_route: application.normalized_route,
            base_cost: application.base_cost,
            source,
        }
    }

    /// 관리 로그인에는 동적 incident 정책과 분리된 고정 한도를 적용합니다.
    pub(crate) fn management_login_rate_limit(&self, method: &str, path: &str) -> Option<u32> {
        (method == "POST" && path == "/api/v1/session")
            .then(|| {
                self.management
                    .as_ref()
                    .map(|value| value.login_rate_limit_rpm)
            })
            .flatten()
    }

    pub(crate) fn body_limit(&self, route_class: RouteClass) -> u64 {
        if route_class == RouteClass::Upload {
            self.upload_max_body_bytes
        } else {
            self.max_body_bytes
        }
    }

    pub(crate) fn rate_limit(&self, route_class: RouteClass) -> Option<u32> {
        if !self.enforces_dynamic_protection() {
            return None;
        }
        match route_class {
            RouteClass::General => self.rate_limit_rpm,
            RouteClass::Strict => self.strict_rate_limit_rpm.or(self.rate_limit_rpm),
            RouteClass::Upload => self.upload_rate_limit_rpm.or(self.rate_limit_rpm),
            RouteClass::ManagementAuth => None,
        }
    }

    /// observe-only 설치에서 동적 throttle·challenge·deny를 실행하지 않습니다.
    pub(crate) fn enforces_dynamic_protection(&self) -> bool {
        self.detection_mode == DetectionMode::Enforce
            && self.inspection_mode == InspectionMode::Profiled
    }

    pub(crate) fn trusts_peer(&self, peer: IpAddr) -> bool {
        self.trusted_proxy_cidrs
            .iter()
            .any(|network| network.contains(&peer))
    }
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod tests;
