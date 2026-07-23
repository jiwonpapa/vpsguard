//! 설정 파일의 leaf certificate와 실제 TLS listener의 leaf를 비교합니다.

use std::fmt::Write as _;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use guard_core::config::CertificateConfig;
use rustls::client::ClientConnection;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    StreamOwned,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{CertificateValidationError, inspect_public_certificate_at, validate_certificate};

/// 실제 listener가 설정 파일과 같은 leaf certificate를 제공하는지 나타냅니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedCertificateState {
    /// 설정 파일과 실제 listener의 leaf certificate가 같습니다.
    Match,
    /// 실제 listener가 다른 leaf certificate를 제공합니다.
    Mismatch,
}

/// 실제 TLS listener와 파일 certificate의 bounded 비교 결과입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServedCertificateReport {
    /// SNI로 전송한 exact DNS 이름입니다.
    pub server_name: String,
    /// DNS를 거치지 않고 연결한 명시적 IP·port입니다.
    pub address: SocketAddr,
    /// 설정 파일 leaf의 SHA-256 fingerprint입니다.
    pub expected_sha256: String,
    /// listener가 제공한 leaf의 SHA-256 fingerprint입니다.
    pub served_sha256: String,
    /// 두 fingerprint의 비교 상태입니다.
    pub state: ServedCertificateState,
}

/// 실제 TLS listener certificate probe 실패입니다.
#[derive(Debug, Error)]
pub enum ServedCertificateProbeError {
    /// probe timeout이 안전 범위를 벗어났습니다.
    #[error("TLS probe timeout은 1..=30초여야 합니다")]
    InvalidTimeout,
    /// SNI에 exact DNS 이름이 아닌 값이 전달됐습니다.
    #[error("TLS probe server name이 잘못됐습니다")]
    InvalidServerName,
    /// 설정 certificate·key·SAN 또는 유효기간 검증이 실패했습니다.
    #[error("TLS probe 전 certificate 사전 검증 실패: {0}")]
    Certificate(#[from] CertificateValidationError),
    /// listener TCP 연결이 실패했습니다.
    #[error("TLS listener 연결 실패: address={address}, cause={source}")]
    Connect {
        /// 연결 대상 IP·port입니다.
        address: SocketAddr,
        /// 원본 I/O 오류입니다.
        source: io::Error,
    },
    /// socket timeout 설정이 실패했습니다.
    #[error("TLS listener timeout 설정 실패: cause={0}")]
    Socket(io::Error),
    /// rustls client 설정을 만들지 못했습니다.
    #[error("TLS probe client 설정 실패")]
    ClientConfiguration,
    /// TLS handshake가 실패했습니다.
    #[error("TLS listener handshake 실패: cause={0}")]
    Handshake(io::Error),
    /// handshake가 peer leaf certificate를 제공하지 않았습니다.
    #[error("TLS listener가 leaf certificate를 제공하지 않았습니다")]
    MissingPeerCertificate,
    /// 내부 관측 상태를 읽지 못했습니다.
    #[error("TLS probe 관측 상태를 읽지 못했습니다")]
    ObservationUnavailable,
}

/// certificate·key를 사전 검증하고 지정된 IP·port가 같은 leaf를 제공하는지 확인합니다.
///
/// DNS와 HTTP 응답에는 의존하지 않습니다. `server_name`은 TLS SNI에만 사용하고
/// 연결은 `address`의 명시적 IP로 수행하므로 CDN 우회 여부도 호출자가 결정합니다.
///
/// # Errors
///
/// 입력, certificate 사전 검증, socket 또는 TLS handshake 실패를 반환합니다.
pub fn inspect_served_certificate(
    certificate: &CertificateConfig,
    server_name: &str,
    address: SocketAddr,
    timeout: StdDuration,
) -> Result<ServedCertificateReport, ServedCertificateProbeError> {
    if timeout < StdDuration::from_secs(1) || timeout > StdDuration::from_secs(30) {
        return Err(ServedCertificateProbeError::InvalidTimeout);
    }
    if server_name.is_empty()
        || server_name.len() > 253
        || server_name.starts_with("*.")
        || server_name.contains('/')
        || server_name.contains(':')
        || server_name.chars().any(char::is_whitespace)
    {
        return Err(ServedCertificateProbeError::InvalidServerName);
    }
    let report_server_name = server_name.to_owned();
    let server_name = ServerName::try_from(report_server_name.clone())
        .map_err(|_| ServedCertificateProbeError::InvalidServerName)?;
    validate_certificate(certificate)?;
    let (certificates, _) =
        inspect_public_certificate_at(certificate, time::OffsetDateTime::now_utc())?;
    let expected = certificates
        .first()
        .cloned()
        .ok_or(CertificateValidationError::MissingCertificate)?;
    let observed = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinnedLeafVerifier {
        expected: expected.clone(),
        observed: Arc::clone(&observed),
        supported: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ServedCertificateProbeError::ClientConfiguration)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|source| ServedCertificateProbeError::Connect { address, source })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(ServedCertificateProbeError::Socket)?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|_| ServedCertificateProbeError::ClientConfiguration)?;
    let mut tls = StreamOwned::new(connection, stream);
    let handshake = while_handshaking(&mut tls);
    let served = observed
        .lock()
        .map_err(|_| ServedCertificateProbeError::ObservationUnavailable)?
        .clone();
    let Some(served) = served else {
        return match handshake {
            Ok(()) => Err(ServedCertificateProbeError::MissingPeerCertificate),
            Err(source) => Err(ServedCertificateProbeError::Handshake(source)),
        };
    };
    let state = if served == expected.as_ref() {
        ServedCertificateState::Match
    } else {
        ServedCertificateState::Mismatch
    };
    if state == ServedCertificateState::Match {
        handshake.map_err(ServedCertificateProbeError::Handshake)?;
    }
    Ok(ServedCertificateReport {
        server_name: report_server_name,
        address,
        expected_sha256: sha256_hex(expected.as_ref()),
        served_sha256: sha256_hex(&served),
        state,
    })
}

fn while_handshaking(
    stream: &mut StreamOwned<ClientConnection, TcpStream>,
) -> Result<(), io::Error> {
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[derive(Debug)]
struct PinnedLeafVerifier {
    expected: CertificateDer<'static>,
    observed: Arc<Mutex<Option<Vec<u8>>>>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut observed = self.observed.lock().map_err(|_| {
            RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        *observed = Some(end_entity.as_ref().to_vec());
        if end_entity.as_ref() != self.expected.as_ref() {
            return Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
#[path = "served/tests.rs"]
mod tests;
