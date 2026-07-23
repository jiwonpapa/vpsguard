//! TLS 파일 검증, 기존 갱신 소유권 감지와 Certbot 보조 계획을 제공합니다.

use std::env;
use std::fs;
use std::io::BufReader;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use guard_core::config::{CertificateConfig, TlsConfig, TlsManagementMode};
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::{OwnedProgram, SystemCommandRunner};

mod served;

pub use served::{
    ServedCertificateProbeError, ServedCertificateReport, ServedCertificateState,
    inspect_served_certificate,
};

const EXPIRING_SOON: Duration = Duration::days(30);
const CERTBOT_LIVE_DIRECTORY: &str = "/etc/letsencrypt/live";
const CERTBOT_RENEWAL_DIRECTORY: &str = "/etc/letsencrypt/renewal";
const ASSISTED_WEBROOT: &str = "/var/lib/vps-guard/acme-webroot";
const CERTBOT_TIMERS: [&str; 2] = ["certbot.timer", "snap.certbot.renew.timer"];

/// 단일 certificate chain의 검증된 공개 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateInspection {
    /// 인증서가 포함해야 하는 설정 domain입니다.
    pub domains: Vec<String>,
    /// leaf certificate 만료 시각 RFC3339입니다.
    pub not_after: String,
    /// 검사 시각부터 만료까지 남은 초입니다.
    pub seconds_remaining: i64,
}

/// 관리 UI에서 표시할 TLS 전체 건강 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsHealth {
    /// HTTPS certificate가 설정되지 않았습니다.
    Disabled,
    /// certificate와 갱신 상태가 정상입니다.
    Valid,
    /// certificate가 30일 안에 만료됩니다.
    ExpiringSoon,
    /// certificate 파일·key·SAN·유효기간 검증이 실패했습니다.
    Invalid,
    /// 자동 갱신 소유권은 있지만 동작하는 갱신 수단을 확인하지 못했습니다.
    RenewalMissing,
}

impl TlsHealth {
    /// API status bar에 사용할 안정 문자열입니다.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Valid => "valid",
            Self::ExpiringSoon => "expiring_soon",
            Self::Invalid => "invalid",
            Self::RenewalMissing => "renewal_missing",
        }
    }
}

/// 현재 certificate 갱신 소유자입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsOwnership {
    /// HTTPS certificate가 아직 없습니다.
    Unmanaged,
    /// 기존 Certbot 또는 명시된 외부 관리자가 소유합니다.
    ExternalManaged,
    /// 명시적 승인 뒤 VPSGuard가 Certbot 구성을 보조합니다.
    VpsguardAssisted,
    /// 관리자가 파일 교체를 직접 소유합니다.
    Manual,
}

/// 자동 갱신 경로의 확인 상태입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsRenewalState {
    /// timer 또는 기존 cron 갱신 경로가 동작합니다.
    Healthy,
    /// 필요한 timer·cron 갱신 경로가 없습니다.
    Missing,
    /// 외부 관리 경로를 VPSGuard가 확인할 수 없습니다.
    Unknown,
    /// 수동 교체 정책이므로 자동 갱신을 기대하지 않습니다.
    Manual,
    /// HTTPS certificate가 없습니다.
    NotApplicable,
}

/// 인증된 관리 API가 제공하는 TLS 소유권·건강 snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsManagementSnapshot {
    /// certificate와 갱신을 합성한 상태입니다.
    pub health: TlsHealth,
    /// 현재 갱신 소유자입니다.
    pub ownership: TlsOwnership,
    /// 자동 갱신 확인 상태입니다.
    pub renewal: TlsRenewalState,
    /// 감지된 manager 이름입니다. 비밀값과 경로는 포함하지 않습니다.
    pub manager: Option<String>,
    /// 검증된 certificate 수입니다.
    pub certificate_count: usize,
    /// 가장 먼저 만료되는 시각입니다.
    pub earliest_expiry: Option<String>,
    /// 검증 실패의 안정 오류 code입니다.
    pub error_code: Option<String>,
    /// 관리자에게 필요한 다음 조치입니다.
    pub next_action: String,
}

/// certificate 파일 사전 검증 실패입니다.
#[derive(Debug, Error)]
pub enum CertificateValidationError {
    /// systemd credential 이름을 해석할 수 없습니다.
    #[error("TLS credential directory를 사용할 수 없습니다")]
    CredentialDirectoryUnavailable,
    /// 상대 TLS credential 이름이 단일 안전 component가 아닙니다.
    #[error("TLS credential 이름이 잘못됐습니다")]
    CredentialNameInvalid,
    /// certificate 또는 private key 파일 읽기 실패입니다.
    #[error("TLS PEM 파일 읽기 실패: kind={kind}, cause={source}")]
    Read {
        /// certificate 또는 private-key입니다.
        kind: &'static str,
        /// 원본 I/O 오류입니다.
        source: std::io::Error,
    },
    /// certificate chain이 비었습니다.
    #[error("TLS certificate chain이 비었습니다")]
    MissingCertificate,
    /// private key가 없습니다.
    #[error("TLS private key가 없습니다")]
    MissingPrivateKey,
    /// certificate를 해석하지 못했습니다.
    #[error("TLS certificate 형식이 잘못됐습니다")]
    InvalidCertificate,
    /// certificate와 private key가 일치하지 않습니다.
    #[error("TLS certificate와 private key가 일치하지 않습니다")]
    KeyMismatch,
    /// certificate가 현재 유효하지 않습니다.
    #[error("TLS certificate가 만료됐거나 아직 유효하지 않습니다")]
    InvalidValidity,
    /// 설정 domain이 SAN에 없습니다.
    #[error("TLS certificate SAN에 domain이 없습니다: {0}")]
    DomainMismatch(String),
    /// rustls protocol 기본값을 만들지 못했습니다.
    #[error("TLS crypto provider 설정을 만들지 못했습니다")]
    CryptoProvider,
}

impl CertificateValidationError {
    fn code(&self) -> &'static str {
        match self {
            Self::CredentialDirectoryUnavailable => "TLS_CREDENTIAL_DIRECTORY_UNAVAILABLE",
            Self::CredentialNameInvalid => "TLS_CREDENTIAL_NAME_INVALID",
            Self::Read { .. } => "TLS_PEM_READ_FAILED",
            Self::MissingCertificate => "TLS_CERTIFICATE_MISSING",
            Self::MissingPrivateKey => "TLS_PRIVATE_KEY_MISSING",
            Self::InvalidCertificate => "TLS_CERTIFICATE_INVALID",
            Self::KeyMismatch => "TLS_KEY_MISMATCH",
            Self::InvalidValidity => "TLS_VALIDITY_INVALID",
            Self::DomainMismatch(_) => "TLS_SAN_MISMATCH",
            Self::CryptoProvider => "TLS_CRYPTO_PROVIDER_INVALID",
        }
    }
}

/// HTTP-01 Certbot 보조 절차의 단일 typed 단계입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertbotPlanStep {
    /// domain DNS가 현재 VPS를 가리키는지 확인합니다.
    VerifyDns,
    /// public 80의 challenge 경로가 도달 가능한지 확인합니다.
    VerifyHttp01,
    /// VPSGuard-owned challenge webroot를 만듭니다.
    CreateWebroot,
    /// 기존 origin에 challenge 경로만 webroot로 연결합니다.
    ConfigureOriginWebroot,
    /// 외부 Certbot client로 staging 또는 production 발급을 수행합니다.
    IssueCertificate,
    /// Certbot renewal timer를 활성화하고 다음 실행을 read-back합니다.
    EnableRenewalTimer,
    /// 성공한 renewal에만 VPSGuard deploy hook을 연결합니다.
    InstallDeployHook,
    /// 파일과 실제 제공 certificate를 비교합니다.
    VerifyServedCertificate,
}

/// 관리자가 승인하기 전 표시하는 Certbot 보조 계획입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertbotAssistedPlan {
    /// plan schema입니다.
    pub schema_version: u32,
    /// HTTP-01 발급 대상 exact domain입니다.
    pub domains: Vec<String>,
    /// ACME 계정 연락처입니다.
    pub email: String,
    /// challenge 전용 webroot입니다.
    pub webroot: PathBuf,
    /// 실행 전 다시 표시할 순서가 고정된 단계입니다.
    pub steps: Vec<CertbotPlanStep>,
    /// 이 plan만으로는 서버를 변경하지 않음을 나타냅니다.
    pub requires_explicit_approval: bool,
    /// 기존 renewal 설정을 덮어쓰지 않음을 나타냅니다.
    pub preserves_existing_manager: bool,
}

/// Certbot 보조 plan 생성 거부입니다.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertbotPlanError {
    /// 설정에서 보조 관리 mode를 선택하지 않았습니다.
    #[error("tls.management은 vpsguard_assisted여야 합니다")]
    AssistedModeRequired,
    /// HTTP-01에서 지원하지 않는 wildcard 또는 잘못된 domain입니다.
    #[error("HTTP-01에 사용할 exact domain이 잘못됐습니다")]
    InvalidDomain,
    /// ACME 연락처 형식이 잘못됐습니다.
    #[error("ACME 연락처 email 형식이 잘못됐습니다")]
    InvalidEmail,
}

/// certificate chain, private key, 현재 유효기간과 SAN을 검사합니다.
///
/// 상대 경로는 현재 service의 `$CREDENTIALS_DIRECTORY` 아래 단일 credential
/// 이름으로만 해석합니다.
///
/// # Errors
///
/// credential, PEM, key 일치, 유효기간 또는 SAN 검증 실패를 반환합니다.
pub fn validate_certificate(
    certificate: &CertificateConfig,
) -> Result<CertificateInspection, CertificateValidationError> {
    validate_certificate_at(certificate, OffsetDateTime::now_utc())
}

/// 설정과 현재 서버 증거를 읽기 전용으로 조사해 TLS 상태를 반환합니다.
#[must_use]
pub fn inspect_tls_management(config: &TlsConfig) -> TlsManagementSnapshot {
    if config.certificates.is_empty() {
        return TlsManagementSnapshot {
            health: TlsHealth::Disabled,
            ownership: TlsOwnership::Unmanaged,
            renewal: TlsRenewalState::NotApplicable,
            manager: None,
            certificate_count: 0,
            earliest_expiry: None,
            error_code: None,
            next_action: "HTTPS를 사용할 때만 인증서 관리 방식을 선택하십시오.".to_owned(),
        };
    }

    let mut inspections = Vec::with_capacity(config.certificates.len());
    for certificate in &config.certificates {
        match inspect_public_certificate_at(certificate, OffsetDateTime::now_utc()) {
            Ok((_, inspection)) => inspections.push(inspection),
            Err(error) => {
                let (ownership, renewal, manager) = management_classification(config, false);
                return TlsManagementSnapshot {
                    health: TlsHealth::Invalid,
                    ownership,
                    renewal,
                    manager,
                    certificate_count: inspections.len(),
                    earliest_expiry: earliest_expiry(&inspections),
                    error_code: Some(error.code().to_owned()),
                    next_action: "certificate·private key 권한, SAN과 유효기간을 확인하십시오."
                        .to_owned(),
                };
            }
        }
    }

    let certbot_renewal = config
        .certificates
        .iter()
        .all(certbot_renewal_configuration_exists);
    let (ownership, renewal, manager) = management_classification(config, certbot_renewal);
    let expiring = inspections
        .iter()
        .any(|inspection| inspection.seconds_remaining <= EXPIRING_SOON.whole_seconds());
    let renewal_required = matches!(
        ownership,
        TlsOwnership::ExternalManaged | TlsOwnership::VpsguardAssisted
    );
    let health = if expiring {
        TlsHealth::ExpiringSoon
    } else if renewal_required && renewal == TlsRenewalState::Missing {
        TlsHealth::RenewalMissing
    } else {
        TlsHealth::Valid
    };
    TlsManagementSnapshot {
        health,
        ownership,
        renewal,
        manager,
        certificate_count: inspections.len(),
        earliest_expiry: earliest_expiry(&inspections),
        error_code: None,
        next_action: next_action(health, ownership, renewal).to_owned(),
    }
}

/// 기존 manager가 없는 서버에서만 HTTP-01 Certbot 보조 plan을 만듭니다.
///
/// # Errors
///
/// 보조 mode, domain 또는 email 계약 위반을 반환합니다.
pub fn build_certbot_assisted_plan(
    mode: TlsManagementMode,
    domains: &[String],
    email: &str,
) -> Result<CertbotAssistedPlan, CertbotPlanError> {
    if mode != TlsManagementMode::VpsguardAssisted {
        return Err(CertbotPlanError::AssistedModeRequired);
    }
    if domains.is_empty()
        || domains.len() > 16
        || domains.iter().any(|domain| {
            domain.starts_with("*.")
                || domain.is_empty()
                || domain.len() > 253
                || domain.contains('/')
                || domain.contains(':')
                || domain.chars().any(char::is_whitespace)
        })
    {
        return Err(CertbotPlanError::InvalidDomain);
    }
    if email.is_empty()
        || email.len() > 254
        || !email.is_ascii()
        || email.chars().any(char::is_whitespace)
        || email
            .split_once('@')
            .is_none_or(|(local, host)| local.is_empty() || host.is_empty() || !host.contains('.'))
    {
        return Err(CertbotPlanError::InvalidEmail);
    }
    Ok(CertbotAssistedPlan {
        schema_version: 1,
        domains: domains.to_vec(),
        email: email.to_owned(),
        webroot: PathBuf::from(ASSISTED_WEBROOT),
        steps: vec![
            CertbotPlanStep::VerifyDns,
            CertbotPlanStep::CreateWebroot,
            CertbotPlanStep::ConfigureOriginWebroot,
            CertbotPlanStep::VerifyHttp01,
            CertbotPlanStep::IssueCertificate,
            CertbotPlanStep::EnableRenewalTimer,
            CertbotPlanStep::InstallDeployHook,
            CertbotPlanStep::VerifyServedCertificate,
        ],
        requires_explicit_approval: true,
        preserves_existing_manager: true,
    })
}

fn validate_certificate_at(
    certificate: &CertificateConfig,
    now: OffsetDateTime,
) -> Result<CertificateInspection, CertificateValidationError> {
    let (certificates, inspection) = inspect_public_certificate_at(certificate, now)?;
    let key_file = resolve_tls_credential_path(&certificate.key_file)?;
    let key_bytes = fs::read(key_file).map_err(|source| CertificateValidationError::Read {
        kind: "private-key",
        source,
    })?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|source| CertificateValidationError::Read {
            kind: "private-key",
            source,
        })?
        .ok_or(CertificateValidationError::MissingPrivateKey)?;
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| CertificateValidationError::CryptoProvider)?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| CertificateValidationError::KeyMismatch)?;

    Ok(inspection)
}

fn inspect_public_certificate_at(
    certificate: &CertificateConfig,
    now: OffsetDateTime,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        CertificateInspection,
    ),
    CertificateValidationError,
> {
    let cert_file = resolve_tls_credential_path(&certificate.cert_file)?;
    let certificate_bytes =
        fs::read(cert_file).map_err(|source| CertificateValidationError::Read {
            kind: "certificate",
            source,
        })?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate_bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CertificateValidationError::Read {
            kind: "certificate",
            source,
        })?;
    let Some(leaf) = certificates.first() else {
        return Err(CertificateValidationError::MissingCertificate);
    };

    let (_, parsed) = parse_x509_certificate(leaf.as_ref())
        .map_err(|_| CertificateValidationError::InvalidCertificate)?;
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    if now.unix_timestamp() < not_before || now.unix_timestamp() > not_after {
        return Err(CertificateValidationError::InvalidValidity);
    }
    let subject_names = parsed
        .subject_alternative_name()
        .map_err(|_| CertificateValidationError::InvalidCertificate)?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some((*value).to_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for domain in &certificate.domains {
        if !subject_names
            .iter()
            .any(|certificate_name| domain_matches(certificate_name, domain))
        {
            return Err(CertificateValidationError::DomainMismatch(domain.clone()));
        }
    }
    let expiry = OffsetDateTime::from_unix_timestamp(not_after)
        .map_err(|_| CertificateValidationError::InvalidCertificate)?;
    Ok((
        certificates,
        CertificateInspection {
            domains: certificate.domains.clone(),
            not_after: expiry.format(&Rfc3339).unwrap_or_default(),
            seconds_remaining: not_after.saturating_sub(now.unix_timestamp()),
        },
    ))
}

fn management_classification(
    config: &TlsConfig,
    certbot_renewal: bool,
) -> (TlsOwnership, TlsRenewalState, Option<String>) {
    match config.management {
        TlsManagementMode::Manual => (TlsOwnership::Manual, TlsRenewalState::Manual, None),
        TlsManagementMode::ExternalManaged if !certbot_renewal => (
            TlsOwnership::ExternalManaged,
            TlsRenewalState::Unknown,
            Some("external".to_owned()),
        ),
        TlsManagementMode::VpsguardAssisted if !certbot_renewal => (
            TlsOwnership::VpsguardAssisted,
            TlsRenewalState::Missing,
            Some("certbot".to_owned()),
        ),
        TlsManagementMode::Auto if !certbot_renewal => {
            (TlsOwnership::Manual, TlsRenewalState::Manual, None)
        }
        TlsManagementMode::Auto | TlsManagementMode::ExternalManaged => {
            let (renewal, manager) = inspect_certbot_renewal();
            (TlsOwnership::ExternalManaged, renewal, manager)
        }
        TlsManagementMode::VpsguardAssisted => {
            let (renewal, manager) = inspect_certbot_renewal();
            (TlsOwnership::VpsguardAssisted, renewal, manager)
        }
    }
}

fn inspect_certbot_renewal() -> (TlsRenewalState, Option<String>) {
    if cron_certbot_exists() {
        return (TlsRenewalState::Healthy, Some("certbot-cron".to_owned()));
    }
    let runner = SystemCommandRunner;
    let mut found_unit = false;
    let mut uncertain = false;
    for timer in CERTBOT_TIMERS {
        if !timer_unit_exists(timer) {
            continue;
        }
        found_unit = true;
        let arguments = vec![
            "show".to_owned(),
            timer.to_owned(),
            "--property=LoadState".to_owned(),
            "--property=ActiveState".to_owned(),
            "--property=UnitFileState".to_owned(),
            "--no-pager".to_owned(),
        ];
        match runner.run(OwnedProgram::Systemctl, &arguments, None, &[]) {
            Ok(output) if systemd_timer_healthy(&output.stdout) => {
                return (TlsRenewalState::Healthy, Some(timer.to_owned()));
            }
            Ok(_) => {}
            Err(_) => uncertain = true,
        }
    }
    if uncertain {
        (TlsRenewalState::Unknown, Some("certbot".to_owned()))
    } else if found_unit {
        (TlsRenewalState::Missing, Some("certbot".to_owned()))
    } else {
        (TlsRenewalState::Missing, None)
    }
}

fn systemd_timer_healthy(output: &str) -> bool {
    let load = property(output, "LoadState") == Some("loaded");
    let active = property(output, "ActiveState") == Some("active");
    let unit_file = property(output, "UnitFileState");
    load && active
        && matches!(
            unit_file,
            Some("enabled" | "enabled-runtime" | "static" | "indirect")
        )
}

fn property<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.split_once('=').filter(|(key, _)| *key == name))
        .map(|(_, value)| value.trim())
}

fn timer_unit_exists(timer: &str) -> bool {
    [
        Path::new("/etc/systemd/system").join(timer),
        Path::new("/run/systemd/system").join(timer),
        Path::new("/usr/lib/systemd/system").join(timer),
        Path::new("/lib/systemd/system").join(timer),
    ]
    .iter()
    .any(|path| path.exists())
}

fn cron_certbot_exists() -> bool {
    let path = Path::new("/etc/cron.d/certbot");
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 64 * 1_024
    {
        return false;
    }
    fs::read_to_string(path).is_ok_and(|source| {
        source.lines().any(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with('#')
                && line.contains("certbot")
                && line.contains("renew")
        })
    })
}

fn certbot_renewal_configuration_exists(certificate: &CertificateConfig) -> bool {
    let lineage = certificate
        .certbot_lineage
        .clone()
        .or_else(|| certbot_lineage(&certificate.cert_file));
    let Some(lineage) = lineage else {
        return false;
    };
    let renewal = Path::new(CERTBOT_RENEWAL_DIRECTORY).join(format!("{lineage}.conf"));
    fs::symlink_metadata(renewal)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
}

fn certbot_lineage(path: &Path) -> Option<String> {
    let relative = path.strip_prefix(CERTBOT_LIVE_DIRECTORY).ok()?;
    let mut components = relative.components();
    let Component::Normal(lineage) = components.next()? else {
        return None;
    };
    let Component::Normal(filename) = components.next()? else {
        return None;
    };
    if components.next().is_some()
        || !matches!(filename.to_str(), Some("fullchain.pem" | "cert.pem"))
    {
        return None;
    }
    lineage.to_str().map(ToOwned::to_owned)
}

/// 절대 TLS 경로를 유지하고 상대값은 현재 service credential로만 해석합니다.
///
/// # Errors
///
/// 상대 credential인데 `$CREDENTIALS_DIRECTORY`가 없으면 거부합니다.
pub fn resolve_tls_credential_path(
    configured: &Path,
) -> Result<PathBuf, CertificateValidationError> {
    let credential_directory = env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    resolve_credential_path(configured, credential_directory.as_deref())
}

fn resolve_credential_path(
    configured: &Path,
    credential_directory: Option<&Path>,
) -> Result<PathBuf, CertificateValidationError> {
    if configured.is_absolute() {
        return Ok(configured.to_path_buf());
    }
    if configured.components().count() != 1
        || !matches!(configured.components().next(), Some(Component::Normal(_)))
    {
        return Err(CertificateValidationError::CredentialNameInvalid);
    }
    let directory =
        credential_directory.ok_or(CertificateValidationError::CredentialDirectoryUnavailable)?;
    Ok(directory.join(configured))
}

fn earliest_expiry(inspections: &[CertificateInspection]) -> Option<String> {
    inspections
        .iter()
        .min_by_key(|inspection| inspection.seconds_remaining)
        .map(|inspection| inspection.not_after.clone())
}

fn next_action(
    health: TlsHealth,
    ownership: TlsOwnership,
    renewal: TlsRenewalState,
) -> &'static str {
    match (health, ownership, renewal) {
        (TlsHealth::ExpiringSoon, _, _) => {
            "만료 전에 현재 소유자의 갱신 dry-run과 실제 제공 인증서를 확인하십시오."
        }
        (TlsHealth::RenewalMissing, TlsOwnership::VpsguardAssisted, _) => {
            "관리 UI에서 Certbot 보조 plan을 검토하고 명시적으로 승인하십시오."
        }
        (TlsHealth::RenewalMissing, _, _) => {
            "기존 인증서 관리자의 timer·cron·deploy hook을 복구하십시오."
        }
        (_, TlsOwnership::Manual, _) => {
            "관리자가 만료 전에 인증서를 원자 교체하고 edge를 reload해야 합니다."
        }
        (_, TlsOwnership::ExternalManaged, TlsRenewalState::Unknown) => {
            "외부 갱신 수단의 상태와 성공 hook을 별도 모니터링하십시오."
        }
        _ => "현재 인증서 관리 설정을 유지하고 만료·served certificate를 관찰하십시오.",
    }
}

fn domain_matches(certificate_name: &str, domain: &str) -> bool {
    let certificate_name = certificate_name.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = certificate_name.strip_prefix("*.") {
        return domain
            .strip_suffix(suffix)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'));
    }
    certificate_name == domain
}

#[cfg(test)]
mod tests {
    use std::fs;

    use guard_core::config::{CertificateConfig, TlsConfig, TlsManagementMode};
    use rcgen::generate_simple_self_signed;

    use super::{
        CertbotPlanError, CertbotPlanStep, TlsHealth, TlsOwnership, TlsRenewalState,
        build_certbot_assisted_plan, management_classification, resolve_credential_path,
        systemd_timer_healthy, validate_certificate,
    };

    #[test]
    fn validates_certificate_and_reports_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let generated = generate_simple_self_signed(vec!["example.test".to_owned()])?;
        let cert_file = directory.path().join("cert.pem");
        let key_file = directory.path().join("key.pem");
        fs::write(&cert_file, generated.cert.pem())?;
        fs::write(&key_file, generated.key_pair.serialize_pem())?;
        let report = validate_certificate(&CertificateConfig {
            domains: vec!["example.test".to_owned()],
            cert_file,
            key_file,
            certbot_lineage: None,
        })?;
        assert!(report.seconds_remaining > 0);
        assert!(report.not_after.ends_with('Z'));
        Ok(())
    }

    #[test]
    fn parses_only_active_loaded_enabled_timer() {
        assert!(systemd_timer_healthy(
            "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"
        ));
        assert!(!systemd_timer_healthy(
            "LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\n"
        ));
    }

    #[test]
    fn assisted_plan_is_read_only_and_rejects_wildcards() -> Result<(), CertbotPlanError> {
        let plan = build_certbot_assisted_plan(
            TlsManagementMode::VpsguardAssisted,
            &["example.com".to_owned()],
            "admin@example.com",
        )?;
        assert!(plan.requires_explicit_approval);
        assert!(plan.preserves_existing_manager);
        assert_eq!(plan.steps[0], CertbotPlanStep::VerifyDns);
        assert_eq!(
            build_certbot_assisted_plan(
                TlsManagementMode::VpsguardAssisted,
                &["*.example.com".to_owned()],
                "admin@example.com",
            ),
            Err(CertbotPlanError::InvalidDomain)
        );
        assert_eq!(TlsHealth::Valid.as_str(), "valid");
        Ok(())
    }

    #[test]
    fn explicit_management_never_claims_an_unverified_timer() {
        let config = TlsConfig {
            management: TlsManagementMode::ExternalManaged,
            certificates: Vec::new(),
        };
        assert_eq!(
            management_classification(&config, false),
            (
                TlsOwnership::ExternalManaged,
                TlsRenewalState::Unknown,
                Some("external".to_owned())
            )
        );
        let assisted = TlsConfig {
            management: TlsManagementMode::VpsguardAssisted,
            certificates: Vec::new(),
        };
        assert_eq!(
            management_classification(&assisted, false).1,
            TlsRenewalState::Missing
        );
    }

    #[test]
    fn credential_names_resolve_only_below_supplied_directory() {
        let resolved = resolve_credential_path(
            std::path::Path::new("tls-cert.pem"),
            Some(std::path::Path::new("/run/credentials/edge")),
        );
        assert!(matches!(
            resolved,
            Ok(path) if path == std::path::Path::new("/run/credentials/edge/tls-cert.pem")
        ));
        assert!(resolve_credential_path(std::path::Path::new("tls-cert.pem"), None).is_err());
        assert!(
            resolve_credential_path(
                std::path::Path::new("../tls-cert.pem"),
                Some(std::path::Path::new("/run/credentials/edge")),
            )
            .is_err()
        );
    }
}
