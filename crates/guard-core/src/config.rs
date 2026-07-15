//! Versioned TOML 설정 계약과 의미 검증을 제공합니다.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 현재 지원하는 설정 schema 버전입니다.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// VPSGuard 전체 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// 설정 schema 버전입니다.
    pub schema_version: u32,
    /// Pingora edge 설정입니다.
    pub edge: EdgeConfig,
    /// Nginx origin 설정입니다.
    pub origin: OriginConfig,
    /// TLS 인증서 설정입니다.
    #[serde(default)]
    pub tls: TlsConfig,
    /// 관리 UI 설정입니다.
    pub ui: UiConfig,
    /// 탐지 profile과 초기 모드입니다.
    pub detection: DetectionConfig,
    /// Cloudflare provider 설정입니다.
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    /// 데이터 보존 설정입니다.
    pub retention: RetentionConfig,
    /// Control 저장 설정입니다.
    #[serde(default)]
    pub storage: StorageConfig,
    /// 읽기 전용 service collector 설정입니다.
    #[serde(default)]
    pub collectors: CollectorsConfig,
}

/// Pingora listener와 정적 안전 한도입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// HTTP listener 주소입니다.
    pub http_bind: SocketAddr,
    /// HTTPS listener 주소입니다. `None`이면 TLS listener를 열지 않습니다.
    #[serde(default)]
    pub https_bind: Option<SocketAddr>,
    /// 요청 Host allowlist입니다.
    pub allowed_hosts: Vec<String>,
    /// 다른 허용 Host를 이 Host로 redirect합니다.
    #[serde(default)]
    pub canonical_host: Option<String>,
    /// forwarded header를 신뢰할 direct peer CIDR입니다.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// 일반 요청 body 최대 크기입니다.
    pub max_body_bytes: u64,
    /// 업로드 요청 body 최대 크기입니다.
    pub upload_max_body_bytes: u64,
    /// 업로드 경로 prefix입니다.
    #[serde(default)]
    pub upload_path_prefixes: Vec<String>,
    /// 고비용 경로 prefix입니다.
    #[serde(default)]
    pub strict_path_prefixes: Vec<String>,
    /// 일반 upstream 연결 제한 시간입니다.
    pub upstream_connect_timeout_ms: u64,
    /// 일반 upstream 읽기 제한 시간입니다.
    pub upstream_read_timeout_ms: u64,
    /// 업로드 upstream 읽기 제한 시간입니다.
    pub upload_upstream_read_timeout_ms: u64,
    /// limiter가 추적할 최대 client 수입니다.
    pub max_tracked_clients: usize,
    /// 일반 경로 client별 분당 한도입니다. `None`이면 적용하지 않습니다.
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
    /// 고비용 경로 client별 분당 한도입니다.
    #[serde(default)]
    pub strict_rate_limit_rpm: Option<u32>,
    /// 업로드 경로 client별 분당 한도입니다.
    #[serde(default)]
    pub upload_rate_limit_rpm: Option<u32>,
    /// non-blocking Unix datagram telemetry socket입니다.
    #[serde(default = "default_telemetry_socket")]
    pub telemetry_socket: PathBuf,
    /// control이 생성한 검증 대상 정책 파일입니다.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,
    /// 정책 파일 확인 주기입니다.
    #[serde(default = "default_policy_reload_interval_ms")]
    pub policy_reload_interval_ms: u64,
    /// browser clearance 서명 secret 파일입니다.
    #[serde(default)]
    pub challenge_secret_file: Option<PathBuf>,
    /// clearance cookie 유효시간입니다.
    #[serde(default = "default_clearance_ttl_seconds")]
    pub clearance_ttl_seconds: u64,
}

/// loopback origin 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginConfig {
    /// Nginx origin 주소입니다.
    pub address: SocketAddr,
    /// origin 프로토콜입니다.
    #[serde(default)]
    pub protocol: OriginProtocol,
    /// TLS origin에서 사용할 SNI입니다.
    #[serde(default)]
    pub sni: Option<String>,
}

/// 지원하는 origin 프로토콜입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OriginProtocol {
    /// 평문 loopback HTTP입니다.
    #[default]
    Http,
    /// TLS origin입니다.
    Https,
}

/// TLS listener와 인증서 목록입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// SNI 인증서 목록입니다.
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
}

/// 한 인증서가 제공할 domain과 PEM 경로입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
    /// 이 인증서를 선택할 domain입니다.
    pub domains: Vec<String>,
    /// PEM certificate chain 경로입니다.
    pub cert_file: PathBuf,
    /// PEM private key 경로입니다.
    pub key_file: PathBuf,
}

/// loopback 관리 UI 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    /// UI listener 주소입니다.
    pub bind: SocketAddr,
    /// Edge가 이 listener로만 전달할 별도 HTTPS 관리 Host입니다.
    #[serde(default)]
    pub public_host: Option<String>,
    /// local 관리자 명령을 받는 peer-credential Unix socket입니다.
    #[serde(default = "default_admin_socket")]
    pub admin_socket: PathBuf,
    /// client별 단회 로그인 시도의 분당 상한입니다.
    #[serde(default = "default_login_rate_limit_rpm")]
    pub login_rate_limit_rpm: u32,
    /// 기본 언어입니다.
    #[serde(default = "default_language")]
    pub language: String,
}

/// 탐지 profile과 첫 설치 모드입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    /// 애플리케이션 route profile입니다.
    pub profile: DetectionProfile,
    /// 첫 설치 동작 모드입니다.
    #[serde(default)]
    pub mode: DetectionMode,
}

/// 초기 애플리케이션 profile입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionProfile {
    /// 범용 PHP profile입니다.
    Php,
    /// GnuBoard 5 profile이며 기존 `gnuboard` 설정의 호환 대상입니다.
    #[serde(rename = "gnuboard5", alias = "gnuboard")]
    Gnuboard5,
    /// GnuBoard 7 profile입니다.
    Gnuboard7,
    /// WordPress profile입니다.
    Wordpress,
}

/// 첫 설치의 자동 조치 범위입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionMode {
    /// 관찰과 리포트만 수행합니다.
    #[default]
    Observe,
    /// 명시적으로 허용된 자동 보호를 수행합니다.
    Enforce,
}

/// Cloudflare provider 설정입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// provider adapter 활성 여부입니다.
    #[serde(default)]
    pub enabled: bool,
    /// 변경 가능한 zone ID입니다.
    #[serde(default)]
    pub zone_id: String,
    /// 변경 가능한 DNS record ID·이름·type allowlist입니다.
    #[serde(default)]
    pub records: Vec<CloudflareRecordConfig>,
    /// 절대 token 파일 경로 또는 systemd credential 이름입니다.
    #[serde(default)]
    pub token_file: PathBuf,
    /// 원본 80/443에 허용할 Cloudflare network CIDR입니다.
    #[serde(default)]
    pub ip_networks: Vec<IpNet>,
}

/// Cloudflare에서 변경할 수 있는 단일 DNS record 식별자입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRecordConfig {
    /// Cloudflare DNS record ID입니다.
    pub id: String,
    /// 완전한 DNS record hostname입니다.
    pub name: String,
    /// 허용 record type입니다.
    pub record_type: DnsRecordType,
}

/// 비상 proxy 전환에서 지원하는 DNS record type입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum DnsRecordType {
    /// IPv4 address record입니다.
    A,
    /// IPv6 address record입니다.
    AAAA,
    /// Canonical name record입니다.
    CNAME,
}

/// 데이터 계층별 보존기간입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// 실시간 ring buffer 보존 초입니다.
    pub live_seconds: u64,
    /// 상세 aggregate 보존 시간입니다.
    pub detail_hours: u64,
    /// 장기 aggregate 보존 일입니다.
    pub aggregate_days: u64,
    /// 사건 보존 일입니다.
    pub incident_days: u64,
    /// 원본 IP 보존 일입니다.
    pub raw_ip_days: u64,
}

/// Control SQLite와 사건 저장 위치입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// SQLite WAL database 파일입니다.
    pub database_path: PathBuf,
    /// 구조화 사건 JSONL directory입니다.
    pub events_directory: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("/var/lib/vps-guard/control.sqlite3"),
            events_directory: PathBuf::from("/var/lib/vps-guard/events"),
        }
    }
}

/// 선택적인 읽기 전용 service collector endpoint입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorsConfig {
    /// Nginx `stub_status` HTTP URL입니다.
    #[serde(default)]
    pub nginx_status_url: Option<String>,
    /// PHP-FPM status HTTP URL입니다.
    #[serde(default)]
    pub php_fpm_status_url: Option<String>,
    /// MySQL handshake 확인 주소입니다.
    #[serde(default)]
    pub mysql_address: Option<SocketAddr>,
    /// Redis PING 확인 주소입니다.
    #[serde(default)]
    pub redis_address: Option<SocketAddr>,
    /// collector별 timeout입니다.
    #[serde(default = "default_collector_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            nginx_status_url: None,
            php_fpm_status_url: None,
            mysql_address: None,
            redis_address: None,
            timeout_ms: default_collector_timeout_ms(),
        }
    }
}

/// 설정 parse 또는 의미 검증 실패입니다.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML 문법 또는 type 오류입니다.
    #[error("설정 TOML을 해석하지 못했습니다: {0}")]
    Parse(#[from] toml::de::Error),
    /// 지원하지 않는 schema 버전입니다.
    #[error("지원하지 않는 설정 schema 버전입니다: expected={expected}, actual={actual}")]
    UnsupportedSchema {
        /// 지원하는 버전입니다.
        expected: u32,
        /// 입력된 버전입니다.
        actual: u32,
    },
    /// 필드 간 의미 제약 위반입니다.
    #[error("잘못된 설정입니다: field={field}, reason={reason}")]
    Invalid {
        /// 문제가 있는 필드 경로입니다.
        field: &'static str,
        /// 실패 이유입니다.
        reason: String,
    },
}

impl GuardConfig {
    /// TOML 문자열을 strict parsing한 뒤 의미 검증합니다.
    ///
    /// # Errors
    ///
    /// 알 수 없는 필드, type 오류, 미래 schema 또는 안전 한도 위반을 반환합니다.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config = toml::from_str::<Self>(input)?;
        config.validate()?;
        Ok(config)
    }

    /// 설정의 범위와 상호 제약을 검증합니다.
    ///
    /// # Errors
    ///
    /// schema, listener, Host, TLS, body, timeout, provider 또는 보존 설정이
    /// 안전 계약을 위반하면 실패합니다.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchema {
                expected: CONFIG_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.edge.allowed_hosts.is_empty() {
            return invalid("edge.allowed_hosts", "최소 한 개의 Host가 필요합니다");
        }
        for host in &self.edge.allowed_hosts {
            validate_host_rule(host, "edge.allowed_hosts")?;
        }
        if let Some(host) = &self.edge.canonical_host {
            validate_host_rule(host, "edge.canonical_host")?;
        }
        for path in self
            .edge
            .upload_path_prefixes
            .iter()
            .chain(&self.edge.strict_path_prefixes)
        {
            if !path.starts_with('/') || path.trim() != path {
                return invalid("edge.path_prefixes", format!("잘못된 경로: {path}"));
            }
        }
        if self.edge.max_body_bytes == 0 {
            return invalid("edge.max_body_bytes", "0보다 커야 합니다");
        }
        if self.edge.upload_max_body_bytes < self.edge.max_body_bytes {
            return invalid(
                "edge.upload_max_body_bytes",
                "일반 body 한도보다 작을 수 없습니다",
            );
        }
        if self.edge.upstream_connect_timeout_ms == 0
            || self.edge.upstream_read_timeout_ms == 0
            || self.edge.upload_upstream_read_timeout_ms == 0
        {
            return invalid("edge.upstream_timeout", "모든 timeout은 0보다 커야 합니다");
        }
        if self.edge.max_tracked_clients == 0 {
            return invalid("edge.max_tracked_clients", "0보다 커야 합니다");
        }
        if self.edge.policy_reload_interval_ms < 100 || self.edge.clearance_ttl_seconds == 0 {
            return invalid(
                "edge.policy_runtime",
                "reload 주기는 100ms 이상이고 clearance TTL은 0보다 커야 합니다",
            );
        }
        if [
            self.edge.rate_limit_rpm,
            self.edge.strict_rate_limit_rpm,
            self.edge.upload_rate_limit_rpm,
        ]
        .into_iter()
        .flatten()
        .any(|limit| limit == 0)
        {
            return invalid("edge.rate_limit_rpm", "설정된 한도는 0보다 커야 합니다");
        }
        if self.origin.address == self.edge.http_bind
            || self.edge.https_bind == Some(self.origin.address)
        {
            return invalid(
                "origin.address",
                "listener와 같은 주소를 사용할 수 없습니다",
            );
        }
        if !self.ui.bind.ip().is_loopback() {
            return invalid("ui.bind", "loopback 주소만 허용합니다");
        }
        if self.ui.bind == self.edge.http_bind || self.edge.https_bind == Some(self.ui.bind) {
            return invalid("ui.bind", "edge listener와 같은 주소를 사용할 수 없습니다");
        }
        if !self.ui.admin_socket.is_absolute() {
            return invalid("ui.admin_socket", "절대 경로가 필요합니다");
        }
        if self.ui.login_rate_limit_rpm == 0 || self.ui.login_rate_limit_rpm > 60 {
            return invalid("ui.login_rate_limit_rpm", "1..=60 범위여야 합니다");
        }
        if self.edge.https_bind.is_some() && self.tls.certificates.is_empty() {
            return invalid("tls.certificates", "HTTPS listener에는 인증서가 필요합니다");
        }
        for certificate in &self.tls.certificates {
            if certificate.domains.is_empty()
                || certificate.cert_file.as_os_str().is_empty()
                || certificate.key_file.as_os_str().is_empty()
            {
                return invalid("tls.certificates", "domain과 PEM 경로가 필요합니다");
            }
            for domain in &certificate.domains {
                validate_host_rule(domain, "tls.certificates.domains")?;
            }
        }
        if let Some(public_host) = self.ui.public_host.as_deref() {
            validate_host_rule(public_host, "ui.public_host")?;
            if public_host.starts_with("*.") {
                return invalid("ui.public_host", "정확한 관리 hostname이 필요합니다");
            }
            if self.edge.https_bind.is_none() {
                return invalid("ui.public_host", "HTTPS listener가 필요합니다");
            }
            if self
                .edge
                .canonical_host
                .as_deref()
                .is_some_and(|host| host.eq_ignore_ascii_case(public_host))
            {
                return invalid(
                    "ui.public_host",
                    "애플리케이션 canonical Host와 분리해야 합니다",
                );
            }
            let covered = self.tls.certificates.iter().any(|certificate| {
                certificate
                    .domains
                    .iter()
                    .any(|rule| host_rule_matches(rule, public_host))
            });
            if !covered {
                return invalid(
                    "ui.public_host",
                    "관리 Host를 포함하는 TLS 인증서가 필요합니다",
                );
            }
        }
        if self.cloudflare.enabled
            && (self.cloudflare.zone_id.trim().is_empty()
                || self.cloudflare.records.is_empty()
                || self.cloudflare.token_file.as_os_str().is_empty()
                || self.cloudflare.ip_networks.is_empty())
        {
            return invalid(
                "cloudflare",
                "활성화 시 zone, record allowlist, token 파일과 IP network가 필요합니다",
            );
        }
        if self.cloudflare.enabled {
            if !is_cloudflare_identifier(&self.cloudflare.zone_id) {
                return invalid(
                    "cloudflare.zone_id",
                    "Cloudflare zone ID는 32자리 소문자 hex여야 합니다",
                );
            }
            if !self.cloudflare.token_file.is_absolute()
                && !is_systemd_credential_name(&self.cloudflare.token_file)
            {
                return invalid(
                    "cloudflare.token_file",
                    "절대 경로 또는 단일 systemd credential 이름이 필요합니다",
                );
            }
            if self.cloudflare.records.len() > 16 {
                return invalid(
                    "cloudflare.records",
                    "단일 hostname에 최대 16개 record만 허용합니다",
                );
            }
            let has_ipv4 = self
                .cloudflare
                .ip_networks
                .iter()
                .any(|network| matches!(network, IpNet::V4(_)));
            let has_ipv6 = self
                .cloudflare
                .ip_networks
                .iter()
                .any(|network| matches!(network, IpNet::V6(_)));
            if !has_ipv4 || !has_ipv6 {
                return invalid(
                    "cloudflare.ip_networks",
                    "origin lock에는 IPv4와 IPv6 Cloudflare network가 모두 필요합니다",
                );
            }
            let mut record_ids = HashSet::with_capacity(self.cloudflare.records.len());
            let record_name = &self.cloudflare.records[0].name;
            if record_name.starts_with("*.") {
                return invalid(
                    "cloudflare.records",
                    "wildcard가 아닌 실제 DNS record 이름이 필요합니다",
                );
            }
            validate_host_rule(record_name, "cloudflare.records")?;
            let mut has_cname = false;
            for record in &self.cloudflare.records {
                if !is_cloudflare_identifier(&record.id) || !record_ids.insert(&record.id) {
                    return invalid(
                        "cloudflare.records",
                        "각 record에는 중복되지 않은 32자리 소문자 hex ID가 필요합니다",
                    );
                }
                if !record.name.eq_ignore_ascii_case(record_name) {
                    return invalid(
                        "cloudflare.records",
                        "한 transaction의 모든 record는 같은 hostname이어야 합니다",
                    );
                }
                validate_host_rule(&record.name, "cloudflare.records")?;
                has_cname |= record.record_type == DnsRecordType::CNAME;
            }
            if has_cname && self.cloudflare.records.len() != 1 {
                return invalid(
                    "cloudflare.records",
                    "CNAME은 같은 hostname의 A·AAAA 또는 다른 CNAME과 함께 둘 수 없습니다",
                );
            }
            let single_served_host = self.edge.allowed_hosts.len() == 1
                && self.edge.allowed_hosts[0].eq_ignore_ascii_case(record_name)
                && self
                    .edge
                    .canonical_host
                    .as_deref()
                    .is_none_or(|canonical| canonical.eq_ignore_ascii_case(record_name));
            if !single_served_host {
                return invalid(
                    "cloudflare.records",
                    "provider hostname과 allowed_hosts·canonical_host가 정확히 일치해야 합니다",
                );
            }
        }
        if self.retention.live_seconds == 0
            || self.retention.detail_hours == 0
            || self.retention.aggregate_days == 0
            || self.retention.incident_days == 0
        {
            return invalid("retention", "보존기간은 0보다 커야 합니다");
        }
        if self.retention.raw_ip_days > self.retention.incident_days {
            return invalid("retention.raw_ip_days", "사건 보존기간보다 길 수 없습니다");
        }
        if self.storage.database_path.as_os_str().is_empty()
            || self.storage.events_directory.as_os_str().is_empty()
        {
            return invalid("storage", "database와 events 경로가 필요합니다");
        }
        if self.collectors.timeout_ms == 0 {
            return invalid("collectors.timeout_ms", "0보다 커야 합니다");
        }
        Ok(())
    }

    /// direct peer가 forwarded header를 제공할 수 있는지 확인합니다.
    #[must_use]
    pub fn trusts_forwarded_peer(&self, peer: IpAddr) -> bool {
        self.edge
            .trusted_proxy_cidrs
            .iter()
            .any(|network| network.contains(&peer))
    }
}

fn is_cloudflare_identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_systemd_credential_name(path: &Path) -> bool {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        return false;
    };
    if components.next().is_some() {
        return false;
    }
    let Some(name) = name.to_str() else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_host_rule(raw: &str, field: &'static str) -> Result<(), ConfigError> {
    let host = raw.trim();
    if host.is_empty() || host != raw || host.contains('/') || host.contains(':') {
        return invalid(field, format!("잘못된 Host 규칙: {raw}"));
    }
    if let Some(suffix) = host.strip_prefix("*.")
        && (suffix.is_empty() || !suffix.contains('.'))
    {
        return invalid(field, format!("잘못된 wildcard Host 규칙: {raw}"));
    }
    Ok(())
}

fn host_rule_matches(rule: &str, host: &str) -> bool {
    if let Some(suffix) = rule.strip_prefix("*.") {
        let rule_suffix = suffix.to_ascii_lowercase();
        let candidate = host.to_ascii_lowercase();
        candidate
            .strip_suffix(&rule_suffix)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    } else {
        rule.eq_ignore_ascii_case(host)
    }
}

fn invalid<T>(field: &'static str, reason: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid {
        field,
        reason: reason.into(),
    })
}

fn default_language() -> String {
    "ko".to_owned()
}

fn default_admin_socket() -> PathBuf {
    PathBuf::from("/run/vps-guard/admin.sock")
}

const fn default_login_rate_limit_rpm() -> u32 {
    10
}

fn default_telemetry_socket() -> PathBuf {
    PathBuf::from("/run/vps-guard/telemetry.sock")
}

fn default_policy_path() -> PathBuf {
    PathBuf::from("/var/lib/vps-guard/policy.json")
}

const fn default_policy_reload_interval_ms() -> u64 {
    1_000
}

const fn default_clearance_ttl_seconds() -> u64 {
    600
}

const fn default_collector_timeout_ms() -> u64 {
    500
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
