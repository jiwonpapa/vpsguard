//! TLS listener 시작 전 공통 certificate validator를 실행합니다.

use guard_core::config::CertificateConfig;

use crate::runtime::RuntimeTlsConfig;

/// TLS 사전 검증 실패입니다.
pub type TlsPreflightError = guard_system::tls::CertificateValidationError;

/// listener가 열리기 전에 certificate chain, key와 모든 설정 domain을 검증합니다.
///
/// # Errors
///
/// PEM 읽기·해석, key 불일치, 유효기간 또는 SAN 불일치를 반환합니다.
pub(crate) fn preflight(tls: &RuntimeTlsConfig) -> Result<(), TlsPreflightError> {
    guard_system::tls::validate_certificate(&CertificateConfig {
        domains: tls.domains.clone(),
        cert_file: tls.cert_file.clone(),
        key_file: tls.key_file.clone(),
        certbot_lineage: None,
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "tls/tests.rs"]
mod tests;
