//! 실제 TLS listener와 leaf certificate 비교 회귀 테스트입니다.

use std::fs;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use guard_core::config::CertificateConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::{ServedCertificateState, StdDuration, inspect_served_certificate};

#[test]
fn compares_the_exact_leaf_served_for_sni() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let expected = generated_certificate(&directory, "expected", "example.test")?;
    let (address, server) = spawn_tls_server(&expected)?;
    let report = inspect_served_certificate(
        &expected,
        "example.test",
        address,
        StdDuration::from_secs(3),
    )?;
    assert_eq!(report.state, ServedCertificateState::Match);
    assert_eq!(report.expected_sha256, report.served_sha256);
    server
        .join()
        .map_err(|_| "TLS fixture server thread failed")?;
    Ok(())
}

#[test]
fn reports_a_different_served_leaf_without_accepting_it() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let expected = generated_certificate(&directory, "expected", "example.test")?;
    let served = generated_certificate(&directory, "served", "example.test")?;
    let (address, server) = spawn_tls_server(&served)?;
    let report = inspect_served_certificate(
        &expected,
        "example.test",
        address,
        StdDuration::from_secs(3),
    )?;
    assert_eq!(report.state, ServedCertificateState::Mismatch);
    assert_ne!(report.expected_sha256, report.served_sha256);
    server
        .join()
        .map_err(|_| "TLS fixture server thread failed")?;
    Ok(())
}

fn generated_certificate(
    directory: &tempfile::TempDir,
    prefix: &str,
    domain: &str,
) -> Result<CertificateConfig, Box<dyn std::error::Error>> {
    let generated = generate_simple_self_signed(vec![domain.to_owned()])?;
    let cert_file = directory.path().join(format!("{prefix}-cert.pem"));
    let key_file = directory.path().join(format!("{prefix}-key.pem"));
    fs::write(&cert_file, generated.cert.pem())?;
    fs::write(&key_file, generated.key_pair.serialize_pem())?;
    Ok(CertificateConfig {
        domains: vec![domain.to_owned()],
        cert_file,
        key_file,
        certbot_lineage: None,
    })
}

fn spawn_tls_server(
    certificate: &CertificateConfig,
) -> Result<(std::net::SocketAddr, thread::JoinHandle<()>), Box<dyn std::error::Error>> {
    let certificate_bytes = fs::read(&certificate.cert_file)?;
    let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key_bytes = fs::read(&certificate.key_file)?;
    let key =
        rustls_pemfile::private_key(&mut key_bytes.as_slice())?.ok_or("missing fixture key")?;
    let server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(StdDuration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(StdDuration::from_secs(3)));
        let Ok(connection) = ServerConnection::new(Arc::new(server_config)) else {
            return;
        };
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            if tls.conn.complete_io(&mut tls.sock).is_err() {
                return;
            }
        }
    });
    Ok((address, server))
}
