//! OPS-012 기존 Nginx·Apache 사이트의 읽기 전용 탐지와 설치 계획을 제공합니다.
//!
//! 탐지는 Ubuntu 표준 enabled-site 경계만 제한적으로 읽습니다. 기본 실행은 파일,
//! service와 ingress를 변경하지 않으며 모호한 설정을 추정해서 자동 지원으로 올리지
//! 않습니다.

mod apache_candidate;
mod nginx_candidate;
#[cfg(test)]
mod tests;

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CommandError, OwnedProgram, SystemCommandRunner};

pub use apache_candidate::{
    ApacheSiteCandidates, build_apache_site_candidates, remove_apache_candidate_stage,
    write_apache_candidate_stage,
};
pub use nginx_candidate::{
    NginxSiteCandidates, build_nginx_site_candidates, remove_nginx_candidate_stage,
    write_nginx_candidate_stage,
};

/// 설치 탐지 report schema입니다.
pub const SITE_SETUP_SCHEMA_VERSION: u32 = 1;
const MAX_ENABLED_FILES: usize = 32;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const SETUP_FIXTURE_STATE: &str = "/run/vps-guard/setup-fixture";

/// VPSGuard 앞뒤에서 사용할 기존 웹서버 종류입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebServerKind {
    /// Ubuntu Nginx입니다.
    Nginx,
    /// Ubuntu Apache 2.4입니다.
    Apache,
}

impl WebServerKind {
    fn service(self) -> &'static str {
        match self {
            Self::Nginx => "nginx.service",
            Self::Apache => "apache2.service",
        }
    }

    fn enabled_root(self) -> &'static str {
        match self {
            Self::Nginx => "/etc/nginx/sites-enabled",
            Self::Apache => "/etc/apache2/sites-enabled",
        }
    }

    fn available_root(self) -> &'static str {
        match self {
            Self::Nginx => "/etc/nginx/sites-available",
            Self::Apache => "/etc/apache2/sites-available",
        }
    }
}

/// 탐지된 사이트의 자동 설치 지원 수준입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupCompatibility {
    /// 표준 단일 HTTPS site이며 자동 준비 후보입니다.
    Supported,
    /// 기존 서비스는 유지하지만 운영자 검토가 필요합니다.
    ManualReview,
    /// 자동 준비를 시도하면 안 되는 충돌 또는 지원 외 환경입니다.
    Rejected,
}

/// 탐지한 PHP 실행 방식입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhpRuntime {
    /// PHP-FPM FastCGI입니다.
    PhpFpm,
    /// Apache mod_php입니다.
    ModPhp,
    /// 현재 bounded site 파일만으로 확정하지 못했습니다.
    Unknown,
}

/// 설치 판정의 안정적 reason code입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetupIssueCode {
    /// Ubuntu 24.04가 아닙니다.
    UnsupportedOperatingSystem,
    /// 지원 웹서버가 active가 아닙니다.
    NoActiveWebServer,
    /// Nginx와 Apache가 동시에 active입니다.
    MultipleActiveWebServers,
    /// enabled site를 찾지 못했습니다.
    NoEnabledSite,
    /// TLS site가 없습니다.
    NoHttpsSite,
    /// TLS site가 둘 이상입니다.
    MultipleHttpsSites,
    /// 기존 reverse proxy 규칙이 있습니다.
    ExistingReverseProxy,
    /// 자동 해석하지 않는 include 또는 macro가 있습니다.
    DynamicConfiguration,
    /// 도메인·root·인증서 같은 필수 필드가 없습니다.
    IncompleteSite,
    /// PHP 실행 방식을 확정하지 못했습니다.
    UnknownPhpRuntime,
}

/// 문제·원인·영향·다음 조치를 분리한 설치 판정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupIssue {
    /// 안정적 reason code입니다.
    pub code: SetupIssueCode,
    /// 사용자가 겪는 문제입니다.
    pub problem: String,
    /// 자동 지원할 수 없는 원인입니다.
    pub cause: String,
    /// 현재 ingress에 미치는 영향입니다.
    pub impact: String,
    /// 안전한 다음 조치입니다.
    pub next_action: String,
}

/// 사이트별 ingress 준비와 transaction 입력 정본입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSetupManifest {
    /// manifest schema입니다.
    pub schema_version: u32,
    /// 기존 웹서버입니다.
    pub web_server: WebServerKind,
    /// canonical HTTPS Host입니다.
    pub server_name: String,
    /// 동일 site의 별칭입니다.
    pub server_aliases: Vec<String>,
    /// 실제 sites-available 파일입니다.
    pub active_config: PathBuf,
    /// sites-enabled symlink입니다.
    pub enabled_link: PathBuf,
    /// application document root입니다.
    pub document_root: PathBuf,
    /// public certificate chain입니다.
    pub certificate: PathBuf,
    /// 기존 웹서버가 계속 소유할 private key 경로입니다.
    pub certificate_key: PathBuf,
    /// 기존 PHP 실행 방식입니다.
    pub php_runtime: PhpRuntime,
}

/// 자동 준비 전에 표시할 단계입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupPlanStep {
    /// 기존 ingress·service·certificate fingerprint를 보존합니다.
    SnapshotExistingIngress,
    /// loopback origin 후보를 준비합니다.
    PrepareLoopbackOrigin,
    /// public 웹서버 후보와 VPSGuard 설정을 검사합니다.
    ValidateCandidates,
    /// public 경로를 짧은 transaction으로 전환합니다.
    SwitchWithAutomaticRollback,
    /// 공개 HTTPS·origin·관리 경계를 read-back합니다.
    VerifyPublicPath,
}

/// `vps-guard setup`의 읽기 전용 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSetupReport {
    /// report schema입니다.
    pub schema_version: u32,
    /// 탐지한 OS ID입니다.
    pub operating_system: String,
    /// 탐지한 OS version입니다.
    pub operating_system_version: String,
    /// 자동 설치 지원 수준입니다.
    pub compatibility: SetupCompatibility,
    /// exactly-one 표준 site일 때만 존재하는 manifest입니다.
    pub site: Option<SiteSetupManifest>,
    /// 판정 근거입니다.
    pub issues: Vec<SetupIssue>,
    /// 지원 site에 적용할 예정 단계입니다.
    pub plan: Vec<SetupPlanStep>,
    /// 읽기 전용 탐지가 수행한 mutation 수이며 항상 0입니다.
    pub mutations_performed: u32,
}

impl SiteSetupReport {
    /// CLI 자동화용 사이트 manifest를 반환합니다.
    ///
    /// # Errors
    ///
    /// 자동 준비 지원 site가 아니면 typed 계약 오류를 반환합니다.
    pub fn supported_site(&self) -> Result<&SiteSetupManifest, SiteSetupError> {
        if self.compatibility == SetupCompatibility::Supported {
            self.site.as_ref().ok_or_else(|| {
                SiteSetupError::Contract("지원 판정에 site manifest가 없습니다".to_owned())
            })
        } else {
            Err(SiteSetupError::Contract(
                "현재 환경은 자동 준비 지원 상태가 아닙니다".to_owned(),
            ))
        }
    }
}

/// bounded 설치 탐지 실패입니다.
#[derive(Debug, Error)]
pub enum SiteSetupError {
    /// root 또는 enabled-site 경계가 잘못됐습니다.
    #[error("site setup 계약 위반: {0}")]
    Contract(String),
    /// bounded filesystem 읽기 실패입니다.
    #[error("site setup I/O 실패: operation={operation}, path={path}, cause={source}")]
    Io {
        /// 실패한 작업입니다.
        operation: &'static str,
        /// 실패한 경로입니다.
        path: String,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// allowlist service 조회 실패입니다.
    #[error(transparent)]
    Command(#[from] CommandError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSite {
    server_name: Option<String>,
    aliases: Vec<String>,
    document_root: Option<PathBuf>,
    certificate: Option<PathBuf>,
    certificate_key: Option<PathBuf>,
    php_runtime: PhpRuntime,
    https: bool,
    existing_proxy: bool,
    dynamic_configuration: bool,
    active_config: PathBuf,
    enabled_link: PathBuf,
}

/// Ubuntu 표준 enabled-site 경계에서 설치 계획을 생성합니다.
///
/// `root`가 `/`가 아니면 test fixture로 간주하고
/// `/run/vps-guard/setup-fixture/<unit>.active` marker만 service 상태로 읽습니다.
///
/// # Errors
///
/// root 경계, 과대 설정, 위험 symlink 또는 filesystem·service 조회 실패를 반환합니다.
pub fn inspect_site_setup(root: &Path) -> Result<SiteSetupReport, SiteSetupError> {
    validate_root(root)?;
    let root =
        fs::canonicalize(root).map_err(|source| io_error("canonicalize_root", root, source))?;
    let (os, version) = inspect_os_release(&root)?;
    if os != "ubuntu" || version != "24.04" {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::Rejected,
            issue(
                SetupIssueCode::UnsupportedOperatingSystem,
                "자동 설치를 지원하지 않는 운영체제입니다.",
                "현재 자동 설치 기준은 Ubuntu 24.04입니다.",
                "기존 웹서버와 사이트는 변경하지 않았습니다.",
                "Ubuntu 24.04에서 다시 실행하거나 수동 설치 절차를 사용하십시오.",
            ),
        ));
    }

    let nginx_active = service_is_active(&root, WebServerKind::Nginx)?;
    let apache_active = service_is_active(&root, WebServerKind::Apache)?;
    let kind = match (nginx_active, apache_active) {
        (true, true) => {
            return Ok(report_with_issue(
                os,
                version,
                SetupCompatibility::Rejected,
                issue(
                    SetupIssueCode::MultipleActiveWebServers,
                    "Nginx와 Apache가 동시에 활성화되어 있습니다.",
                    "public ingress 소유자를 하나로 확정할 수 없습니다.",
                    "잘못된 자동 편입이 기존 사이트를 우회할 수 있어 아무것도 변경하지 않았습니다.",
                    "80/443을 실제 소유하는 웹서버 하나를 명시적으로 정리한 뒤 다시 실행하십시오.",
                ),
            ));
        }
        (true, false) => WebServerKind::Nginx,
        (false, true) => WebServerKind::Apache,
        (false, false) => {
            return Ok(report_with_issue(
                os,
                version,
                SetupCompatibility::Rejected,
                issue(
                    SetupIssueCode::NoActiveWebServer,
                    "활성 Nginx 또는 Apache를 찾지 못했습니다.",
                    "지원 웹서버 service가 active가 아닙니다.",
                    "기존 port와 파일은 변경하지 않았습니다.",
                    "기존 사이트 웹서버를 정상 기동한 뒤 다시 실행하십시오.",
                ),
            ));
        }
    };

    let sites = discover_sites(&root, kind)?;
    if sites.is_empty() {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::NoEnabledSite,
                "활성 웹서버에서 enabled site를 찾지 못했습니다.",
                "Ubuntu 표준 sites-enabled symlink가 없습니다.",
                "자동 후보를 생성하지 않았습니다.",
                "sites-enabled 경계와 활성 virtual host를 확인하십시오.",
            ),
        ));
    }
    let https_sites: Vec<_> = sites.into_iter().filter(|site| site.https).collect();
    if https_sites.is_empty() {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::NoHttpsSite,
                "활성 HTTPS site를 찾지 못했습니다.",
                "enabled virtual host에 443 listener와 certificate가 함께 없습니다.",
                "TLS와 public ingress를 변경하지 않았습니다.",
                "기존 인증서와 HTTPS virtual host를 먼저 정상화하십시오.",
            ),
        ));
    }
    if https_sites.len() != 1 {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::MultipleHttpsSites,
                "HTTPS site가 둘 이상입니다.",
                format!(
                    "자동 설치는 exactly-one site만 지원합니다: count={}",
                    https_sites.len()
                ),
                "어느 site도 자동 선택하거나 변경하지 않았습니다.",
                "관리할 도메인을 명시적으로 고르는 다중 site 지원 전까지 수동 계획을 사용하십시오.",
            ),
        ));
    }
    evaluate_site(os, version, kind, https_sites.into_iter().next())
}

fn evaluate_site(
    os: String,
    version: String,
    kind: WebServerKind,
    selected: Option<ParsedSite>,
) -> Result<SiteSetupReport, SiteSetupError> {
    let site = selected.ok_or_else(|| {
        SiteSetupError::Contract("exactly-one HTTPS site 선택이 사라졌습니다".to_owned())
    })?;
    if site.existing_proxy {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::ExistingReverseProxy,
                "기존 reverse proxy 규칙이 있습니다.",
                "ProxyPass 또는 proxy_pass가 이미 application 요청 경로를 소유합니다.",
                "기존 upstream을 우회하지 않도록 자동 후보를 생성하지 않았습니다.",
                "기존 proxy route와 VPSGuard 편입 위치를 수동으로 검토하십시오.",
            ),
        ));
    }
    if site.dynamic_configuration {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::DynamicConfiguration,
                "동적으로 합성되는 virtual host입니다.",
                "지원 allowlist 밖의 Include, Macro 또는 변수 기반 핵심 경로가 있습니다.",
                "실제 실행 설정과 다른 후보를 만들 수 있어 자동 준비하지 않았습니다.",
                "정적 단일 site로 분리하거나 수동 계획에서 include 결과를 확정하십시오.",
            ),
        ));
    }
    if site.php_runtime == PhpRuntime::Unknown {
        return Ok(report_with_issue(
            os,
            version,
            SetupCompatibility::ManualReview,
            issue(
                SetupIssueCode::UnknownPhpRuntime,
                "PHP 실행 방식을 확정하지 못했습니다.",
                "site 또는 표준 enabled module에서 PHP-FPM·mod_php 증거가 없습니다.",
                "정적 파일은 유지되지만 PHP 요청 경로를 자동 편입하지 않았습니다.",
                "PHP handler를 확인한 뒤 다시 실행하십시오.",
            ),
        ));
    }
    let (server_name, document_root, certificate, certificate_key) = match (
        site.server_name,
        site.document_root,
        site.certificate,
        site.certificate_key,
    ) {
        (Some(server_name), Some(document_root), Some(certificate), Some(certificate_key))
            if valid_dns_name(&server_name)
                && safe_absolute(&document_root)
                && safe_certificate_path(&certificate)
                && safe_certificate_path(&certificate_key) =>
        {
            (server_name, document_root, certificate, certificate_key)
        }
        _ => {
            return Ok(report_with_issue(
                os,
                version,
                SetupCompatibility::ManualReview,
                issue(
                    SetupIssueCode::IncompleteSite,
                    "사이트 필수 설정을 확정하지 못했습니다.",
                    "ServerName, DocumentRoot, certificate 또는 private key 경로가 없거나 안전 경계 밖입니다.",
                    "기존 site를 변경하지 않았습니다.",
                    "표준 절대 경로와 exact DNS ServerName을 설정한 뒤 다시 실행하십시오.",
                ),
            ));
        }
    };
    let manifest = SiteSetupManifest {
        schema_version: SITE_SETUP_SCHEMA_VERSION,
        web_server: kind,
        server_name,
        server_aliases: site
            .aliases
            .into_iter()
            .filter(|alias| valid_dns_name(alias))
            .take(16)
            .collect(),
        active_config: site.active_config,
        enabled_link: site.enabled_link,
        document_root,
        certificate,
        certificate_key,
        php_runtime: site.php_runtime,
    };
    Ok(SiteSetupReport {
        schema_version: SITE_SETUP_SCHEMA_VERSION,
        operating_system: os,
        operating_system_version: version,
        compatibility: SetupCompatibility::Supported,
        site: Some(manifest),
        issues: Vec::new(),
        plan: vec![
            SetupPlanStep::SnapshotExistingIngress,
            SetupPlanStep::PrepareLoopbackOrigin,
            SetupPlanStep::ValidateCandidates,
            SetupPlanStep::SwitchWithAutomaticRollback,
            SetupPlanStep::VerifyPublicPath,
        ],
        mutations_performed: 0,
    })
}

fn discover_sites(root: &Path, kind: WebServerKind) -> Result<Vec<ParsedSite>, SiteSetupError> {
    let enabled_root = logical(root, Path::new(kind.enabled_root()));
    if !enabled_root.is_dir() {
        return Ok(Vec::new());
    }
    let available_root = logical(root, Path::new(kind.available_root()));
    let mut entries = fs::read_dir(&enabled_root)
        .map_err(|source| io_error("read_enabled_sites", &enabled_root, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error("collect_enabled_sites", &enabled_root, source))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    if entries.len() > MAX_ENABLED_FILES {
        return Err(SiteSetupError::Contract(format!(
            "enabled site 수가 상한을 넘습니다: count={}, max={MAX_ENABLED_FILES}",
            entries.len()
        )));
    }
    let mut sites = Vec::new();
    for entry in entries {
        let enabled_path = entry.path();
        let metadata = fs::symlink_metadata(&enabled_path)
            .map_err(|source| io_error("enabled_site_metadata", &enabled_path, source))?;
        if !metadata.file_type().is_symlink() {
            return Err(SiteSetupError::Contract(format!(
                "enabled site가 symlink가 아닙니다: {}",
                enabled_path.display()
            )));
        }
        let target = fs::read_link(&enabled_path)
            .map_err(|source| io_error("read_enabled_site_link", &enabled_path, source))?;
        let resolved = if target.is_absolute() {
            logical(root, &target)
        } else {
            enabled_path
                .parent()
                .ok_or_else(|| {
                    SiteSetupError::Contract("enabled site parent가 없습니다".to_owned())
                })?
                .join(target)
        };
        let canonical = fs::canonicalize(&resolved)
            .map_err(|source| io_error("canonicalize_enabled_site", &resolved, source))?;
        let available = fs::canonicalize(&available_root)
            .map_err(|source| io_error("canonicalize_available_root", &available_root, source))?;
        if !canonical.starts_with(&available) {
            return Err(SiteSetupError::Contract(format!(
                "enabled site target이 sites-available 밖입니다: {}",
                canonical.display()
            )));
        }
        let size = fs::metadata(&canonical)
            .map_err(|source| io_error("enabled_site_size", &canonical, source))?
            .len();
        if size > MAX_CONFIG_BYTES {
            return Err(SiteSetupError::Contract(format!(
                "site 설정이 상한을 넘습니다: path={}, bytes={size}",
                canonical.display()
            )));
        }
        let source = fs::read_to_string(&canonical)
            .map_err(|error| io_error("read_enabled_site", &canonical, error))?;
        let active_logical = from_root(root, &canonical)?;
        let enabled_logical = from_root(root, &enabled_path)?;
        let mut parsed = match kind {
            WebServerKind::Nginx => parse_nginx_sites(&source, &active_logical, &enabled_logical),
            WebServerKind::Apache => {
                parse_apache_sites(root, &source, &active_logical, &enabled_logical)
            }
        };
        sites.append(&mut parsed);
    }
    Ok(sites)
}

fn parse_nginx_sites(source: &str, active: &Path, enabled: &Path) -> Vec<ParsedSite> {
    let mut blocks = Vec::new();
    let mut collecting = false;
    let mut depth = 0_i32;
    let mut current = Vec::new();
    for original in source.lines() {
        let line = strip_comment(original);
        let trimmed = line.trim();
        if !collecting && starts_nginx_server(trimmed) {
            collecting = true;
            depth = brace_delta(trimmed);
            current.push(trimmed.to_owned());
            continue;
        }
        if collecting {
            current.push(trimmed.to_owned());
            depth += brace_delta(trimmed);
            if depth <= 0 {
                blocks.push(std::mem::take(&mut current));
                collecting = false;
            }
        }
    }
    blocks
        .into_iter()
        .map(|block| {
            let joined = block.join("\n");
            let listen = directives(&block, "listen");
            let certificate = first_directive(&block, "ssl_certificate").map(PathBuf::from);
            let certificate_key = first_directive(&block, "ssl_certificate_key").map(PathBuf::from);
            let server_names = first_directive(&block, "server_name")
                .map(split_words)
                .unwrap_or_default();
            let server_name = server_names.first().cloned();
            let aliases = server_names.into_iter().skip(1).collect();
            let dynamic_configuration = block.iter().any(|line| {
                directive_value(line, "include")
                    .is_some_and(|value| !allowed_tls_include(value, WebServerKind::Nginx))
                    || critical_value_has_variable(line)
            });
            ParsedSite {
                server_name,
                aliases,
                document_root: first_directive(&block, "root").map(PathBuf::from),
                certificate,
                certificate_key,
                php_runtime: if joined.contains("fastcgi_pass") || joined.contains("proxy:unix:") {
                    PhpRuntime::PhpFpm
                } else {
                    PhpRuntime::Unknown
                },
                https: listen.iter().any(|value| listen_is_https(value)),
                existing_proxy: joined.lines().any(|line| {
                    directive_value(line, "proxy_pass").is_some()
                        || directive_value(line, "grpc_pass").is_some()
                }),
                dynamic_configuration,
                active_config: active.to_path_buf(),
                enabled_link: enabled.to_path_buf(),
            }
        })
        .collect()
}

fn parse_apache_sites(root: &Path, source: &str, active: &Path, enabled: &Path) -> Vec<ParsedSite> {
    let mut blocks = Vec::new();
    let mut current = Vec::new();
    let mut collecting = false;
    for original in source.lines() {
        let trimmed = strip_comment(original).trim().to_owned();
        if !collecting && trimmed.to_ascii_lowercase().starts_with("<virtualhost ") {
            collecting = true;
            current.push(trimmed);
            continue;
        }
        if collecting {
            let closing = trimmed.eq_ignore_ascii_case("</virtualhost>");
            current.push(trimmed);
            if closing {
                blocks.push(std::mem::take(&mut current));
                collecting = false;
            }
        }
    }
    let global_runtime = apache_global_runtime(root);
    blocks
        .into_iter()
        .map(|block| {
            let joined = block.join("\n");
            let opening = block.first().cloned().unwrap_or_default();
            let server_name = first_apache_directive(&block, "ServerName");
            let aliases = first_apache_directive(&block, "ServerAlias")
                .map(split_words)
                .unwrap_or_default();
            let block_runtime = if joined.to_ascii_lowercase().contains("proxy:unix:")
                || joined.to_ascii_lowercase().contains("proxy:fcgi")
            {
                PhpRuntime::PhpFpm
            } else if joined
                .to_ascii_lowercase()
                .contains("application/x-httpd-php")
            {
                PhpRuntime::ModPhp
            } else {
                global_runtime
            };
            let dynamic_configuration = block.iter().any(|line| {
                apache_directive_value(line, "Include")
                    .is_some_and(|value| !allowed_tls_include(value, WebServerKind::Apache))
                    || line.to_ascii_lowercase().contains("<macro")
                    || critical_value_has_variable(line)
            });
            ParsedSite {
                server_name,
                aliases,
                document_root: first_apache_directive(&block, "DocumentRoot").map(PathBuf::from),
                certificate: first_apache_directive(&block, "SSLCertificateFile")
                    .map(PathBuf::from),
                certificate_key: first_apache_directive(&block, "SSLCertificateKeyFile")
                    .map(PathBuf::from),
                php_runtime: block_runtime,
                https: apache_virtual_host_is_https(&opening)
                    || first_apache_directive(&block, "SSLEngine")
                        .is_some_and(|value| value.eq_ignore_ascii_case("on")),
                existing_proxy: block.iter().any(|line| {
                    apache_directive_value(line, "ProxyPass").is_some()
                        || apache_directive_value(line, "ProxyPassMatch").is_some()
                }),
                dynamic_configuration,
                active_config: active.to_path_buf(),
                enabled_link: enabled.to_path_buf(),
            }
        })
        .collect()
}

fn apache_global_runtime(root: &Path) -> PhpRuntime {
    let modules = logical(root, Path::new("/etc/apache2/mods-enabled"));
    if read_names(&modules)
        .iter()
        .any(|name| name.starts_with("php") && (name.ends_with(".load") || name.ends_with(".conf")))
    {
        return PhpRuntime::ModPhp;
    }
    let conf = logical(root, Path::new("/etc/apache2/conf-enabled"));
    if read_names(&conf)
        .iter()
        .any(|name| name.starts_with("php") && name.contains("-fpm"))
    {
        PhpRuntime::PhpFpm
    } else {
        PhpRuntime::Unknown
    }
}

fn read_names(path: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(MAX_ENABLED_FILES)
        .collect()
}

fn service_is_active(root: &Path, kind: WebServerKind) -> Result<bool, SiteSetupError> {
    if root != Path::new("/") {
        let marker = logical(
            root,
            &Path::new(SETUP_FIXTURE_STATE).join(format!("{}.active", kind.service())),
        );
        return Ok(fs::read_to_string(marker)
            .ok()
            .is_some_and(|value| value.trim() == "active"));
    }
    let output = SystemCommandRunner.run_accepting(
        OwnedProgram::Systemctl,
        &[
            "is-active".to_owned(),
            "--quiet".to_owned(),
            kind.service().to_owned(),
        ],
        None,
        &[],
        &[0, 3, 4],
    )?;
    Ok(output.audit.exit_code == Some(0))
}

fn inspect_os_release(root: &Path) -> Result<(String, String), SiteSetupError> {
    let path = logical(root, Path::new("/etc/os-release"));
    let content =
        fs::read_to_string(&path).map_err(|source| io_error("read_os_release", &path, source))?;
    let value = |key: &str| {
        content.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name == key).then(|| value.trim_matches('"').to_ascii_lowercase())
        })
    };
    Ok((
        value("ID").unwrap_or_else(|| "unknown".to_owned()),
        value("VERSION_ID").unwrap_or_else(|| "unknown".to_owned()),
    ))
}

fn report_with_issue(
    os: String,
    version: String,
    compatibility: SetupCompatibility,
    issue: SetupIssue,
) -> SiteSetupReport {
    SiteSetupReport {
        schema_version: SITE_SETUP_SCHEMA_VERSION,
        operating_system: os,
        operating_system_version: version,
        compatibility,
        site: None,
        issues: vec![issue],
        plan: Vec::new(),
        mutations_performed: 0,
    }
}

fn issue(
    code: SetupIssueCode,
    problem: impl Into<String>,
    cause: impl Into<String>,
    impact: impl Into<String>,
    next_action: impl Into<String>,
) -> SetupIssue {
    SetupIssue {
        code,
        problem: problem.into(),
        cause: cause.into(),
        impact: impact.into(),
        next_action: next_action.into(),
    }
}

fn validate_root(root: &Path) -> Result<(), SiteSetupError> {
    if root.is_absolute()
        && !root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Ok(())
    } else {
        Err(SiteSetupError::Contract(format!(
            "setup root가 절대 정규 경로가 아닙니다: {}",
            root.display()
        )))
    }
}

fn logical(root: &Path, absolute: &Path) -> PathBuf {
    if root == Path::new("/") {
        absolute.to_path_buf()
    } else {
        root.join(absolute.strip_prefix("/").unwrap_or(absolute))
    }
}

fn from_root(root: &Path, actual: &Path) -> Result<PathBuf, SiteSetupError> {
    if root == Path::new("/") {
        return Ok(actual.to_path_buf());
    }
    let suffix = actual.strip_prefix(root).map_err(|_| {
        SiteSetupError::Contract(format!(
            "fixture path가 setup root 밖입니다: {}",
            actual.display()
        ))
    })?;
    Ok(Path::new("/").join(suffix))
}

fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut quote = '\0';
    let mut output = String::new();
    for character in line.chars() {
        if matches!(character, '"' | '\'') {
            if quoted && character == quote {
                quoted = false;
            } else if !quoted {
                quoted = true;
                quote = character;
            }
        }
        if character == '#' && !quoted {
            break;
        }
        output.push(character);
    }
    output
}

fn starts_nginx_server(line: &str) -> bool {
    let compact = line.split_whitespace().collect::<Vec<_>>();
    compact.first() == Some(&"server") && line.contains('{')
}

fn brace_delta(line: &str) -> i32 {
    let mut quoted = false;
    let mut quote = '\0';
    let mut delta = 0_i32;
    for character in line.chars() {
        if matches!(character, '"' | '\'') {
            if quoted && character == quote {
                quoted = false;
            } else if !quoted {
                quoted = true;
                quote = character;
            }
        } else if !quoted {
            if character == '{' {
                delta += 1;
            } else if character == '}' {
                delta -= 1;
            }
        }
    }
    delta
}

fn directive_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix(name)?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some(rest.trim().trim_end_matches(';').trim())
}

fn apache_directive_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let (actual, rest) = trimmed.split_once(char::is_whitespace)?;
    actual
        .eq_ignore_ascii_case(name)
        .then(|| rest.trim().trim_matches('"'))
}

fn directives(lines: &[String], name: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| directive_value(line, name))
        .map(str::to_owned)
        .collect()
}

fn first_directive(lines: &[String], name: &str) -> Option<String> {
    lines
        .iter()
        .find_map(|line| directive_value(line, name))
        .map(unquote)
}

fn first_apache_directive(lines: &[String], name: &str) -> Option<String> {
    lines
        .iter()
        .find_map(|line| apache_directive_value(line, name))
        .map(unquote)
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

fn split_words(value: String) -> Vec<String> {
    value
        .split_whitespace()
        .map(unquote)
        .filter(|value| !value.is_empty())
        .collect()
}

fn listen_is_https(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        token == "443"
            || token.ends_with(":443")
            || token.starts_with("443")
            || token.eq_ignore_ascii_case("ssl")
    })
}

fn apache_virtual_host_is_https(opening: &str) -> bool {
    opening
        .trim_matches(|character| character == '<' || character == '>')
        .split_whitespace()
        .skip(1)
        .any(|address| address.ends_with(":443") || address == "443")
}

fn allowed_tls_include(value: &str, kind: WebServerKind) -> bool {
    let value = unquote(value);
    match kind {
        WebServerKind::Nginx => matches!(
            value.as_str(),
            "/etc/letsencrypt/options-ssl-nginx.conf" | "/etc/letsencrypt/ssl-dhparams.pem"
        ),
        WebServerKind::Apache => {
            value == "/etc/letsencrypt/options-ssl-apache.conf"
                || value == "/etc/letsencrypt/options-ssl-apache2.conf"
        }
    }
}

fn critical_value_has_variable(line: &str) -> bool {
    [
        "root",
        "ssl_certificate",
        "ssl_certificate_key",
        "DocumentRoot",
        "SSLCertificateFile",
    ]
    .iter()
    .any(|name| {
        directive_value(line, name)
            .or_else(|| apache_directive_value(line, name))
            .is_some_and(|value| value.contains('$') || value.contains("${"))
    })
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

fn safe_certificate_path(path: &Path) -> bool {
    safe_absolute(path)
        && (path.starts_with("/etc/letsencrypt/live/") || path.starts_with("/etc/ssl/"))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> SiteSetupError {
    SiteSetupError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}
