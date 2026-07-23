//! Versioned TOML 설정 계약과 의미 검증을 제공합니다.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crawler::{CrawlerNetwork, CrawlerProvider};

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
    /// host firewall 소유권과 standalone backend 설정입니다.
    #[serde(default)]
    pub firewall: FirewallConfig,
    /// 탐지 profile과 초기 모드입니다.
    pub detection: DetectionConfig,
    /// declared bot과 verified crawler 정책입니다.
    #[serde(default)]
    pub bot_policy: BotPolicyConfig,
    /// 애플리케이션 앞단 보안 정책입니다.
    #[serde(default)]
    pub security: SecurityConfig,
    /// 외부 ModSecurity·OWASP CRS adapter 정책입니다.
    #[serde(default)]
    pub waf: WafConfig,
    /// Cloudflare provider 설정입니다.
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    /// 외부 관리자 notification 설정입니다.
    #[serde(default)]
    pub notifications: NotificationConfig,
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
    /// 동시에 origin으로 전달할 수 있는 최대 HTTP 요청 수입니다.
    #[serde(default = "default_max_in_flight_requests")]
    pub max_in_flight_requests: u64,
    /// downstream body read·response write·drain 제한 시간입니다.
    #[serde(default = "default_downstream_io_timeout_ms")]
    pub downstream_io_timeout_ms: u64,
    /// HTTP/1 downstream이 유지해야 하는 최소 응답 전송률입니다.
    #[serde(default = "default_downstream_min_send_rate_bps")]
    pub downstream_min_send_rate_bps: usize,
    /// 한 downstream keepalive 연결이 처리할 최대 요청 수입니다.
    #[serde(default = "default_keepalive_request_limit")]
    pub keepalive_request_limit: u32,
    /// client limit에 곱할 IPv4 /24·IPv6 /64 prefix 예산입니다.
    #[serde(default = "default_prefix_rate_limit_multiplier")]
    pub prefix_rate_limit_multiplier: u32,
    /// client limit에 곱할 route class aggregate 예산입니다.
    #[serde(default = "default_route_rate_limit_multiplier")]
    pub route_rate_limit_multiplier: u32,
    /// client limit에 곱할 전체 listener aggregate 예산입니다.
    #[serde(default = "default_global_rate_limit_multiplier")]
    pub global_rate_limit_multiplier: u32,
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
    /// 기존 갱신 소유권을 유지할 TLS 관리 정책입니다.
    #[serde(default)]
    pub management: TlsManagementMode,
    /// SNI 인증서 목록입니다.
    #[serde(default)]
    pub certificates: Vec<CertificateConfig>,
}

/// 인증서 갱신을 누가 소유하는지 결정하는 정책입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsManagementMode {
    /// Certbot renewal과 timer를 읽기 전용으로 감지하고, 없으면 수동으로 판정합니다.
    #[default]
    Auto,
    /// 서버에 이미 존재하는 외부 갱신 수단을 그대로 사용합니다.
    ExternalManaged,
    /// 명시적 plan·승인 뒤 VPSGuard가 Certbot 구성을 보조합니다.
    VpsguardAssisted,
    /// 자동 갱신 없이 관리자가 인증서 교체를 소유합니다.
    Manual,
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
    /// systemd credential을 써도 기존 renewal을 찾을 수 있는 Certbot lineage 이름입니다.
    #[serde(default)]
    pub certbot_lineage: Option<String>,
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
    /// 관리 Host의 외부 HTTPS port입니다.
    #[serde(default = "default_https_port")]
    pub public_port: u16,
    /// 관리 Host의 public TLS 종료 위치입니다.
    #[serde(default)]
    pub tls_termination: UiTlsTermination,
    /// 관리자 credential을 검증할 provider입니다.
    #[serde(default)]
    pub auth_provider: AdminAuthProvider,
    /// PAM client가 사용할 `/etc/pam.d` service 이름입니다.
    #[serde(default = "default_pam_service")]
    pub pam_service: String,
    /// PAM 인증 뒤 허용할 Unix group입니다.
    #[serde(default = "default_pam_allowed_group")]
    pub pam_allowed_group: String,
    /// local 관리자 명령을 받는 peer-credential Unix socket입니다.
    #[serde(default = "default_admin_socket")]
    pub admin_socket: PathBuf,
    /// PAM·UFW를 root helper에 위임하는 Unix socket입니다.
    #[serde(default = "default_privileged_socket")]
    pub privileged_socket: PathBuf,
    /// client별 단회 로그인 시도의 분당 상한입니다.
    #[serde(default = "default_login_rate_limit_rpm")]
    pub login_rate_limit_rpm: u32,
    /// 기본 언어입니다.
    #[serde(default = "default_language")]
    pub language: String,
}

/// 관리 Host의 HTTPS 종료 소유자입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTlsTermination {
    /// Pingora edge가 직접 public TLS를 종료합니다.
    #[default]
    Edge,
    /// trusted loopback Apache·Nginx가 public TLS를 종료하고 edge로 전달합니다.
    TrustedExternal,
}

/// 관리 UI가 사용할 credential provider입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuthProvider {
    /// 기존 VPSGuard 전용 Argon2id 계정을 사용하는 호환 mode입니다.
    #[default]
    Local,
    /// Linux-PAM 서버 계정과 allowlisted group을 사용합니다.
    Pam,
}

/// host firewall 변경 소유권 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// 설치 topology에 따른 firewall mutation mode입니다.
    #[serde(default)]
    pub mode: FirewallMode,
    /// 절대로 deny하지 않고 전후 연결성을 확인할 관리 SSH port입니다.
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            mode: FirewallMode::Disabled,
            ssh_port: default_ssh_port(),
        }
    }
}

/// host firewall mutation 소유자입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// VPSGuard standalone 설치가 typed UFW rule을 소유합니다.
    StandaloneUfw,
    /// JW-agent가 host firewall을 소유하고 VPSGuard는 변경을 거부합니다.
    JwAgentDelegated,
    /// host firewall 기능을 사용하지 않습니다.
    #[default]
    Disabled,
}

/// 외부 WAF adapter 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WafConfig {
    /// off, detection-only 또는 GnuBoard 조정 후 차단 mode입니다.
    #[serde(default)]
    pub mode: WafMode,
    /// 지원하는 외부 engine입니다.
    #[serde(default)]
    pub adapter: WafAdapter,
    /// app별 rule 제외 파일입니다.
    #[serde(default)]
    pub exclusions_file: Option<PathBuf>,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            mode: WafMode::Off,
            adapter: WafAdapter::ModSecurityOwaspCrs,
            exclusions_file: None,
        }
    }
}

/// 외부 WAF enforcement 단계입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    /// 외부 WAF를 사용하지 않습니다.
    #[default]
    Off,
    /// 사건만 기록하고 요청은 통과시킵니다.
    Detection,
    /// 검증된 app 예외를 적용한 뒤 차단합니다.
    TunedEnforce,
}

/// 지원하는 외부 WAF engine입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafAdapter {
    /// Apache ModSecurity v2와 배포판 OWASP CRS package입니다.
    #[default]
    ModSecurityOwaspCrs,
}

/// 탐지 profile과 첫 설치 모드입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    /// 애플리케이션 route profile입니다.
    pub profile: DetectionProfile,
    /// HTTP parsing 뒤 적용할 분석 계층입니다.
    #[serde(default)]
    pub inspection: InspectionMode,
    /// 첫 설치 동작 모드입니다.
    #[serde(default)]
    pub mode: DetectionMode,
}

/// HTTP 요청에 적용할 분석 범위입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionMode {
    /// app profile, route class와 행동 기반 동적 정책을 사용합니다.
    #[default]
    Profiled,
    /// app profile·행동 판정을 생략하고 정적 HTTP 안전 불변조건만 유지합니다.
    ProtocolOnly,
}

impl InspectionMode {
    /// 설정·API·CLI에 쓰는 안정된 문자열입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Profiled => "profiled",
            Self::ProtocolOnly => "protocol_only",
        }
    }
}

/// response header와 인증 시도 보호 정책입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// `nosniff`와 최소 referrer policy를 응답에 적용합니다.
    #[serde(default = "default_true")]
    pub baseline_response_headers: bool,
    /// origin의 구현·버전 노출 header를 제거합니다.
    #[serde(default = "default_true")]
    pub strip_origin_headers: bool,
    /// Content Security Policy 적용 단계입니다.
    #[serde(default)]
    pub csp_mode: CspMode,
    /// app profile 기본값을 대체하는 site CSP입니다.
    #[serde(default)]
    pub csp_policy: Option<String>,
    /// HTTPS 응답의 HSTS `max-age`입니다. 0이면 비활성화합니다.
    #[serde(default)]
    pub hsts_max_age_seconds: u64,
    /// app profile 인증 경로의 client별 분당 한도입니다. 0이면 비활성화합니다.
    #[serde(default = "default_auth_rate_limit_rpm")]
    pub auth_rate_limit_rpm: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            baseline_response_headers: true,
            strip_origin_headers: true,
            csp_mode: CspMode::ReportOnly,
            csp_policy: None,
            hsts_max_age_seconds: 0,
            auth_rate_limit_rpm: default_auth_rate_limit_rpm(),
        }
    }
}

/// Content Security Policy의 적용 단계입니다.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CspMode {
    /// CSP header를 추가하지 않습니다.
    Off,
    /// 위반을 차단하지 않고 브라우저 진단만 생성합니다.
    #[default]
    ReportOnly,
    /// 검증된 CSP를 실제로 강제합니다.
    Enforce,
}

impl CspMode {
    /// 설정·API에 쓰는 안정된 문자열입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::ReportOnly => "report_only",
            Self::Enforce => "enforce",
        }
    }
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

/// declared bot 차단과 검색 crawler allowlist입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BotPolicyConfig {
    /// enforce mode에서 미허용 declared bot과 위조 crawler를 거부합니다.
    #[serde(default)]
    pub block_unapproved_declared_bots: bool,
    /// 허용할 검색 crawler provider입니다.
    #[serde(default)]
    pub allowed_crawlers: Vec<CrawlerProvider>,
    /// 공식 provider feed에서 가져와 pin한 network입니다.
    #[serde(default)]
    pub crawler_networks: Vec<CrawlerNetwork>,
    /// install-time updater가 만든 공식 network JSON입니다.
    #[serde(default)]
    pub crawler_networks_file: Option<PathBuf>,
}

/// Cloudflare provider 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    /// DNS-only cache 소진을 기다릴 수 있는 최대 기존 record TTL입니다.
    #[serde(default = "default_cloudflare_max_dns_ttl_seconds")]
    pub max_dns_ttl_seconds: u32,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            zone_id: String::new(),
            records: Vec::new(),
            token_file: PathBuf::new(),
            ip_networks: Vec::new(),
            max_dns_ttl_seconds: default_cloudflare_max_dns_ttl_seconds(),
        }
    }
}

/// 주요 보호 사건을 외부 관리자에게 전달하는 HTTPS webhook 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationConfig {
    /// 외부 notification worker 활성 여부입니다.
    #[serde(default)]
    pub enabled: bool,
    /// query·fragment·내장 인증 정보가 없는 HTTPS webhook URL입니다.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// 선택적인 bearer token의 절대 경로 또는 systemd credential 이름입니다.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// process 안에서 대기할 최대 사건 수입니다.
    #[serde(default = "default_notification_queue_capacity")]
    pub queue_capacity: usize,
    /// 사건 하나의 최대 전송 시도 횟수입니다.
    #[serde(default = "default_notification_max_attempts")]
    pub max_attempts: u8,
    /// 재시도 사이 첫 backoff입니다.
    #[serde(default = "default_notification_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// 단일 HTTPS 요청의 전체 제한 시간입니다.
    #[serde(default = "default_notification_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: None,
            token_file: None,
            queue_capacity: default_notification_queue_capacity(),
            max_attempts: default_notification_max_attempts(),
            initial_backoff_ms: default_notification_initial_backoff_ms(),
            request_timeout_ms: default_notification_request_timeout_ms(),
        }
    }
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
    /// 운영 감사 기록 보존 일입니다.
    #[serde(default = "default_audit_retention_days")]
    pub audit_days: u64,
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
    /// SQLite 본체와 WAL의 사용량 경고·쓰기 제한 예산입니다.
    #[serde(default = "default_storage_max_database_bytes")]
    pub max_database_bytes: u64,
    /// 새 traffic sample 저장을 중단할 최소 filesystem 여유입니다.
    #[serde(default = "default_storage_min_disk_free_bytes")]
    pub min_disk_free_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("/var/lib/vps-guard/control.sqlite3"),
            events_directory: PathBuf::from("/var/lib/vps-guard/events"),
            max_database_bytes: default_storage_max_database_bytes(),
            min_disk_free_bytes: default_storage_min_disk_free_bytes(),
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
    /// cgroup v2 mount root입니다.
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    /// 관리자가 명시적으로 허용한 핵심 service입니다.
    #[serde(default)]
    pub services: Vec<ServiceCollectorConfig>,
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
            cgroup_root: default_cgroup_root(),
            services: Vec::new(),
            timeout_ms: default_collector_timeout_ms(),
        }
    }
}

/// allowlist된 핵심 service의 cgroup과 semantic metric 설정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCollectorConfig {
    /// UI와 API에 표시할 안정된 식별자입니다.
    pub name: String,
    /// allowlist된 systemd service unit입니다.
    pub unit: String,
    /// semantic metric parser 종류입니다.
    pub kind: ServiceCollectorKind,
    /// cgroup root 아래 상대 경로입니다. 기본값은 `system.slice/<unit>`입니다.
    #[serde(default)]
    pub cgroup_path: Option<PathBuf>,
    /// Nginx·Apache·PHP-FPM의 loopback status URL입니다.
    #[serde(default)]
    pub status_url: Option<String>,
    /// 인증 없는 loopback Redis 주소입니다.
    #[serde(default)]
    pub address: Option<SocketAddr>,
    /// MySQL 또는 인증 Redis connection URL을 담은 systemd credential 이름입니다.
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
}

/// 핵심 service의 semantic metric 종류입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCollectorKind {
    /// Nginx `stub_status`입니다.
    Nginx,
    /// Apache `mod_status?auto`입니다.
    Apache,
    /// PHP-FPM status text입니다.
    PhpFpm,
    /// MySQL 또는 MariaDB global status입니다.
    Mysql,
    /// Redis INFO입니다.
    Redis,
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
        if !(1..=65_535).contains(&self.edge.max_in_flight_requests) {
            return invalid(
                "edge.max_in_flight_requests",
                "1 이상 65535 이하여야 합니다",
            );
        }
        if !(100..=300_000).contains(&self.edge.downstream_io_timeout_ms) {
            return invalid(
                "edge.downstream_io_timeout_ms",
                "100ms 이상 300000ms 이하여야 합니다",
            );
        }
        if !(1..=10 * 1_024 * 1_024).contains(&self.edge.downstream_min_send_rate_bps) {
            return invalid(
                "edge.downstream_min_send_rate_bps",
                "1 이상 10485760 이하여야 합니다",
            );
        }
        if !(1..=10_000).contains(&self.edge.keepalive_request_limit) {
            return invalid(
                "edge.keepalive_request_limit",
                "1 이상 10000 이하여야 합니다",
            );
        }
        if self.edge.prefix_rate_limit_multiplier == 0
            || self.edge.route_rate_limit_multiplier < self.edge.prefix_rate_limit_multiplier
            || self.edge.global_rate_limit_multiplier < self.edge.route_rate_limit_multiplier
        {
            return invalid(
                "edge.rate_limit_multiplier",
                "prefix > 0, prefix <= route <= global 순서여야 합니다",
            );
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
        if self.security.hsts_max_age_seconds > 63_072_000 {
            return invalid("security.hsts_max_age_seconds", "0부터 2년 사이여야 합니다");
        }
        let mut crawler_providers = HashSet::new();
        for provider in &self.bot_policy.allowed_crawlers {
            if !crawler_providers.insert(*provider) {
                return invalid("bot_policy.allowed_crawlers", "중복 provider가 있습니다");
            }
        }
        let mut network_providers = HashSet::new();
        for entry in &self.bot_policy.crawler_networks {
            if entry.cidrs.is_empty() || !network_providers.insert(entry.provider) {
                return invalid(
                    "bot_policy.crawler_networks",
                    "provider별 비어 있지 않은 network 목록 하나가 필요합니다",
                );
            }
        }
        if self.bot_policy.block_unapproved_declared_bots
            && self
                .bot_policy
                .allowed_crawlers
                .iter()
                .any(|provider| !network_providers.contains(provider))
            && self.bot_policy.crawler_networks_file.is_none()
        {
            return invalid(
                "bot_policy.crawler_networks",
                "허용 crawler의 공식 network 목록이 필요합니다",
            );
        }
        if let Some(path) = &self.bot_policy.crawler_networks_file
            && !path.is_absolute()
        {
            return invalid("bot_policy.crawler_networks_file", "절대 경로가 필요합니다");
        }
        if self.security.auth_rate_limit_rpm > 600 {
            return invalid(
                "security.auth_rate_limit_rpm",
                "0 또는 1..=600 범위여야 합니다",
            );
        }
        if let Some(path) = &self.waf.exclusions_file
            && (!path.is_absolute() || path.as_os_str().is_empty())
        {
            return invalid("waf.exclusions_file", "절대 경로가 필요합니다");
        }
        if self.waf.mode == WafMode::TunedEnforce && self.waf.exclusions_file.is_none() {
            return invalid(
                "waf.exclusions_file",
                "tuned_enforce에는 검증된 app 예외 파일이 필요합니다",
            );
        }
        if self.security.csp_mode == CspMode::Off && self.security.csp_policy.is_some() {
            return invalid(
                "security.csp_policy",
                "CSP off에서는 site policy를 함께 둘 수 없습니다",
            );
        }
        if let Some(policy) = self.security.csp_policy.as_deref()
            && (policy.is_empty()
                || policy.len() > 4_096
                || policy.trim() != policy
                || !policy.is_ascii()
                || policy.bytes().any(|byte| byte.is_ascii_control()))
        {
            return invalid(
                "security.csp_policy",
                "공백 경계와 제어문자 없는 4KiB 이하 ASCII policy가 필요합니다",
            );
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
        if !self.ui.privileged_socket.is_absolute() {
            return invalid("ui.privileged_socket", "절대 경로가 필요합니다");
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
            for (field, path) in [
                ("tls.certificates.cert_file", &certificate.cert_file),
                ("tls.certificates.key_file", &certificate.key_file),
            ] {
                if !path.is_absolute() && !is_systemd_credential_name(path) {
                    return invalid(
                        field,
                        "절대 경로 또는 단일 systemd credential 이름이 필요합니다",
                    );
                }
            }
            if certificate.cert_file == certificate.key_file {
                return invalid(
                    "tls.certificates",
                    "certificate와 private key 경로는 달라야 합니다",
                );
            }
            if certificate
                .certbot_lineage
                .as_deref()
                .is_some_and(|lineage| {
                    lineage.is_empty()
                        || lineage.len() > 128
                        || !lineage.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                        || matches!(lineage, "." | "..")
                })
            {
                return invalid(
                    "tls.certificates.certbot_lineage",
                    "Certbot lineage는 안전한 단일 이름이어야 합니다",
                );
            }
            for domain in &certificate.domains {
                validate_host_rule(domain, "tls.certificates.domains")?;
            }
        }
        if self.ui.tls_termination == UiTlsTermination::TrustedExternal
            && self.ui.public_host.is_none()
        {
            return invalid(
                "ui.tls_termination",
                "trusted external TLS에는 별도 관리 Host가 필요합니다",
            );
        }
        if let Some(public_host) = self.ui.public_host.as_deref() {
            validate_host_rule(public_host, "ui.public_host")?;
            if public_host.starts_with("*.") {
                return invalid("ui.public_host", "정확한 관리 hostname이 필요합니다");
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
            match self.ui.tls_termination {
                UiTlsTermination::Edge => {
                    if self.edge.https_bind.is_none() {
                        return invalid("ui.public_host", "HTTPS listener가 필요합니다");
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
                UiTlsTermination::TrustedExternal => {
                    if !self
                        .edge
                        .trusted_proxy_cidrs
                        .iter()
                        .any(|network| network.addr().is_loopback())
                    {
                        return invalid(
                            "ui.tls_termination",
                            "trusted external TLS peer의 loopback CIDR가 필요합니다",
                        );
                    }
                }
            }
        }
        if self.ui.public_host.is_some() && self.ui.public_port == 0 {
            return invalid("ui.public_port", "1..=65535 범위여야 합니다");
        }
        if self.ui.auth_provider == AdminAuthProvider::Pam {
            if !is_safe_identity_name(&self.ui.pam_service) {
                return invalid(
                    "ui.pam_service",
                    "영문자·숫자·점·밑줄·하이픈으로 된 안전한 이름이 필요합니다",
                );
            }
            if !is_safe_identity_name(&self.ui.pam_allowed_group)
                || self.ui.pam_allowed_group.eq_ignore_ascii_case("root")
            {
                return invalid(
                    "ui.pam_allowed_group",
                    "root가 아닌 전용 Unix group 이름이 필요합니다",
                );
            }
        }
        if self.firewall.ssh_port == 0 {
            return invalid("firewall.ssh_port", "1..=65535 범위여야 합니다");
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
            if !(60..=3_600).contains(&self.cloudflare.max_dns_ttl_seconds) {
                return invalid(
                    "cloudflare.max_dns_ttl_seconds",
                    "60..=3600초 범위여야 합니다",
                );
            }
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
        if self.notifications.enabled && self.notifications.webhook_url.is_none() {
            return invalid(
                "notifications.webhook_url",
                "notification 활성화 시 HTTPS webhook URL이 필요합니다",
            );
        }
        if let Some(raw_url) = self.notifications.webhook_url.as_deref() {
            let parsed = url::Url::parse(raw_url).ok();
            let valid = parsed.as_ref().is_some_and(|url| {
                url.scheme() == "https"
                    && url.host().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            });
            if !valid {
                return invalid(
                    "notifications.webhook_url",
                    "인증 정보·query·fragment 없는 HTTPS URL만 허용합니다",
                );
            }
        }
        if let Some(path) = self.notifications.token_file.as_deref()
            && !path.is_absolute()
            && !is_systemd_credential_name(path)
        {
            return invalid(
                "notifications.token_file",
                "절대 경로 또는 단일 systemd credential 이름이 필요합니다",
            );
        }
        if !(16..=4_096).contains(&self.notifications.queue_capacity) {
            return invalid("notifications.queue_capacity", "16..=4096 범위여야 합니다");
        }
        if !(1..=5).contains(&self.notifications.max_attempts) {
            return invalid("notifications.max_attempts", "1..=5 범위여야 합니다");
        }
        if !(100..=60_000).contains(&self.notifications.initial_backoff_ms) {
            return invalid(
                "notifications.initial_backoff_ms",
                "100..=60000ms 범위여야 합니다",
            );
        }
        if !(500..=30_000).contains(&self.notifications.request_timeout_ms) {
            return invalid(
                "notifications.request_timeout_ms",
                "500..=30000ms 범위여야 합니다",
            );
        }
        if self.retention.live_seconds == 0
            || self.retention.detail_hours == 0
            || self.retention.aggregate_days == 0
            || self.retention.incident_days == 0
            || self.retention.audit_days == 0
        {
            return invalid("retention", "보존기간은 0보다 커야 합니다");
        }
        if self.retention.live_seconds > 86_400 {
            return invalid(
                "retention.live_seconds",
                "1초 live ring은 최대 86,400초여야 합니다",
            );
        }
        if self.retention.raw_ip_days > self.retention.incident_days {
            return invalid("retention.raw_ip_days", "사건 보존기간보다 길 수 없습니다");
        }
        if self.storage.database_path.as_os_str().is_empty()
            || self.storage.events_directory.as_os_str().is_empty()
        {
            return invalid("storage", "database와 events 경로가 필요합니다");
        }
        if !self.storage.database_path.is_absolute() || !self.storage.events_directory.is_absolute()
        {
            return invalid("storage", "database와 events는 절대 경로여야 합니다");
        }
        if !(16 * 1_024 * 1_024..=16 * 1_024 * 1_024 * 1_024)
            .contains(&self.storage.max_database_bytes)
        {
            return invalid(
                "storage.max_database_bytes",
                "16 MiB부터 16 GiB 사이여야 합니다",
            );
        }
        if !(64 * 1_024 * 1_024..=64 * 1_024 * 1_024 * 1_024)
            .contains(&self.storage.min_disk_free_bytes)
        {
            return invalid(
                "storage.min_disk_free_bytes",
                "64 MiB부터 64 GiB 사이여야 합니다",
            );
        }
        if self.collectors.timeout_ms == 0 {
            return invalid("collectors.timeout_ms", "0보다 커야 합니다");
        }
        if self.collectors.timeout_ms > 10_000 {
            return invalid("collectors.timeout_ms", "최대 10초여야 합니다");
        }
        if self.collectors.cgroup_root != Path::new("/sys/fs/cgroup") {
            return invalid(
                "collectors.cgroup_root",
                "지원하는 cgroup v2 root는 /sys/fs/cgroup입니다",
            );
        }
        for (field, url) in [
            (
                "collectors.nginx_status_url",
                &self.collectors.nginx_status_url,
            ),
            (
                "collectors.php_fpm_status_url",
                &self.collectors.php_fpm_status_url,
            ),
        ] {
            if let Some(url) = url {
                validate_loopback_http_url(url, field)?;
            }
        }
        for (field, address) in [
            ("collectors.mysql_address", self.collectors.mysql_address),
            ("collectors.redis_address", self.collectors.redis_address),
        ] {
            if address.is_some_and(|address| !address.ip().is_loopback()) {
                return invalid(field, "loopback 주소만 허용합니다");
            }
        }
        let legacy_service_configured = self.collectors.nginx_status_url.is_some()
            || self.collectors.php_fpm_status_url.is_some()
            || self.collectors.mysql_address.is_some()
            || self.collectors.redis_address.is_some();
        if legacy_service_configured && !self.collectors.services.is_empty() {
            return invalid(
                "collectors",
                "legacy endpoint와 allowlist service 설정을 함께 사용할 수 없습니다",
            );
        }
        validate_service_collectors(&self.collectors.services)?;
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

fn validate_service_collectors(services: &[ServiceCollectorConfig]) -> Result<(), ConfigError> {
    if services.len() > 16 {
        return invalid("collectors.services", "핵심 service는 최대 16개입니다");
    }
    let mut names = HashSet::with_capacity(services.len());
    let mut units = HashSet::with_capacity(services.len());
    for service in services {
        if service.name.is_empty()
            || service.name.len() > 64
            || !service
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !names.insert(&service.name)
        {
            return invalid(
                "collectors.services.name",
                "중복되지 않은 64자 이하 안전 식별자가 필요합니다",
            );
        }
        if service.unit.len() > 128
            || !service.unit.ends_with(".service")
            || service.unit.contains('/')
            || !service.unit.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'@' | b':' | b'\\')
            })
            || !units.insert(&service.unit)
        {
            return invalid(
                "collectors.services.unit",
                "중복되지 않은 안전한 systemd .service unit이 필요합니다",
            );
        }
        if let Some(path) = service.cgroup_path.as_deref()
            && (!is_safe_relative_path(path, 8) || path.file_name() != Some(service.unit.as_ref()))
        {
            return invalid(
                "collectors.services.cgroup_path",
                "cgroup root 아래 안전한 상대 경로여야 합니다",
            );
        }
        match service.kind {
            ServiceCollectorKind::Nginx
            | ServiceCollectorKind::Apache
            | ServiceCollectorKind::PhpFpm => {
                let Some(status_url) = service.status_url.as_deref() else {
                    return invalid(
                        "collectors.services.status_url",
                        "HTTP service에는 loopback status URL이 필요합니다",
                    );
                };
                validate_loopback_http_url(status_url, "collectors.services.status_url")?;
                if service.address.is_some() || service.credential_file.is_some() {
                    return invalid(
                        "collectors.services",
                        "HTTP service에는 address나 credential_file을 함께 둘 수 없습니다",
                    );
                }
            }
            ServiceCollectorKind::Mysql => {
                if service.status_url.is_some()
                    || service.address.is_some()
                    || service.credential_file.is_none()
                {
                    return invalid(
                        "collectors.services",
                        "MySQL에는 connection URL credential_file만 필요합니다",
                    );
                }
            }
            ServiceCollectorKind::Redis => {
                if service.status_url.is_some()
                    || service.address.is_some() == service.credential_file.is_some()
                {
                    return invalid(
                        "collectors.services",
                        "Redis에는 loopback address 또는 credential_file 중 하나가 필요합니다",
                    );
                }
                if service
                    .address
                    .is_some_and(|address| !address.ip().is_loopback())
                {
                    return invalid(
                        "collectors.services.address",
                        "Redis는 loopback 주소만 허용합니다",
                    );
                }
            }
        }
        if let Some(path) = service.credential_file.as_deref()
            && !path.is_absolute()
            && !is_systemd_credential_name(path)
        {
            return invalid(
                "collectors.services.credential_file",
                "절대 경로 또는 단일 systemd credential 이름이 필요합니다",
            );
        }
    }
    Ok(())
}

fn validate_loopback_http_url(value: &str, field: &'static str) -> Result<(), ConfigError> {
    let parsed = url::Url::parse(value)
        .ok()
        .filter(|url| url.scheme() == "http")
        .filter(|url| url.username().is_empty() && url.password().is_none())
        .filter(|url| url.fragment().is_none())
        .filter(loopback_url_host);
    if parsed.is_none() {
        return invalid(field, "인증 정보 없는 loopback HTTP URL만 허용합니다");
    }
    Ok(())
}

fn loopback_url_host(value: &url::Url) -> bool {
    match value.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn is_safe_relative_path(path: &Path, max_components: usize) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().count() <= max_components
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_safe_identity_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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

fn default_privileged_socket() -> PathBuf {
    PathBuf::from("/run/vps-guard-privileged/control.sock")
}

fn default_pam_service() -> String {
    "vps-guard".to_owned()
}

fn default_pam_allowed_group() -> String {
    "vpsguard-admin".to_owned()
}

const fn default_login_rate_limit_rpm() -> u32 {
    10
}

const fn default_https_port() -> u16 {
    443
}

const fn default_auth_rate_limit_rpm() -> u32 {
    10
}

const fn default_ssh_port() -> u16 {
    22
}

const fn default_true() -> bool {
    true
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

const fn default_prefix_rate_limit_multiplier() -> u32 {
    32
}

const fn default_route_rate_limit_multiplier() -> u32 {
    128
}

const fn default_global_rate_limit_multiplier() -> u32 {
    256
}

const fn default_max_in_flight_requests() -> u64 {
    1_024
}

const fn default_downstream_io_timeout_ms() -> u64 {
    30_000
}

const fn default_downstream_min_send_rate_bps() -> usize {
    1_024
}

const fn default_keepalive_request_limit() -> u32 {
    1_000
}

const fn default_cloudflare_max_dns_ttl_seconds() -> u32 {
    300
}

const fn default_notification_queue_capacity() -> usize {
    256
}

const fn default_notification_max_attempts() -> u8 {
    3
}

const fn default_notification_initial_backoff_ms() -> u64 {
    500
}

const fn default_notification_request_timeout_ms() -> u64 {
    5_000
}

const fn default_collector_timeout_ms() -> u64 {
    500
}

fn default_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

const fn default_audit_retention_days() -> u64 {
    365
}

const fn default_storage_max_database_bytes() -> u64 {
    512 * 1_024 * 1_024
}

const fn default_storage_min_disk_free_bytes() -> u64 {
    256 * 1_024 * 1_024
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
