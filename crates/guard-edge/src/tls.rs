//! TLS listener 시작 전 PEM, key 일치, 유효기간과 domain을 검증합니다.

use std::fs;
use std::io::BufReader;

use rustls::ServerConfig;
use thiserror::Error;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::runtime::RuntimeTlsConfig;

/// TLS 사전 검증 실패입니다.
#[derive(Debug, Error)]
pub enum TlsPreflightError {
    /// PEM 파일 읽기 실패입니다.
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
    /// PEM certificate를 해석하지 못했습니다.
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
}

/// listener가 열리기 전에 certificate chain, key와 모든 설정 domain을 검증합니다.
///
/// # Errors
///
/// PEM 읽기·해석, key 불일치, 유효기간 또는 SAN 불일치를 반환합니다.
pub(crate) fn preflight(tls: &RuntimeTlsConfig) -> Result<(), TlsPreflightError> {
    let certificate_bytes = fs::read(&tls.cert_file).map_err(|source| TlsPreflightError::Read {
        kind: "certificate",
        source,
    })?;
    let key_bytes = fs::read(&tls.key_file).map_err(|source| TlsPreflightError::Read {
        kind: "private-key",
        source,
    })?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate_bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsPreflightError::Read {
            kind: "certificate",
            source,
        })?;
    let Some(leaf) = certificates.first() else {
        return Err(TlsPreflightError::MissingCertificate);
    };
    let leaf = leaf.clone();
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
        .map_err(|source| TlsPreflightError::Read {
            kind: "private-key",
            source,
        })?
        .ok_or(TlsPreflightError::MissingPrivateKey)?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| TlsPreflightError::KeyMismatch)?;

    let (_, parsed) =
        parse_x509_certificate(leaf.as_ref()).map_err(|_| TlsPreflightError::InvalidCertificate)?;
    if !parsed.validity().is_valid() {
        return Err(TlsPreflightError::InvalidValidity);
    }
    let subject_names = parsed
        .subject_alternative_name()
        .map_err(|_| TlsPreflightError::InvalidCertificate)?
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
    for domain in &tls.domains {
        if !subject_names
            .iter()
            .any(|certificate_name| domain_matches(certificate_name, domain))
        {
            return Err(TlsPreflightError::DomainMismatch(domain.clone()));
        }
    }
    Ok(())
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
#[path = "tls/tests.rs"]
mod tests;
