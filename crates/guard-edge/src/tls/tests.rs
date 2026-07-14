//! TLS 사전 검증 회귀 테스트입니다.

use std::fs;

use rcgen::generate_simple_self_signed;

use super::{TlsPreflightError, preflight};
use crate::runtime::RuntimeTlsConfig;

fn files(
    directory: &tempfile::TempDir,
    names: Vec<String>,
) -> Result<RuntimeTlsConfig, Box<dyn std::error::Error>> {
    let generated = generate_simple_self_signed(names.clone())?;
    let cert_file = directory.path().join("cert.pem");
    let key_file = directory.path().join("key.pem");
    fs::write(&cert_file, generated.cert.pem())?;
    fs::write(&key_file, generated.key_pair.serialize_pem())?;
    Ok(RuntimeTlsConfig {
        listen_addr: "127.0.0.1:18443".to_owned(),
        cert_file,
        key_file,
        domains: names,
    })
}

#[test]
fn accepts_matching_certificate_key_and_domain() -> Result<(), Box<dyn std::error::Error>> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let directory = tempfile::tempdir()?;
    let tls = files(&directory, vec!["example.test".to_owned()])?;
    preflight(&tls)?;
    Ok(())
}

#[test]
fn rejects_domain_not_in_san() -> Result<(), Box<dyn std::error::Error>> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let directory = tempfile::tempdir()?;
    let mut tls = files(&directory, vec!["example.test".to_owned()])?;
    tls.domains = vec!["other.test".to_owned()];
    assert!(matches!(
        preflight(&tls),
        Err(TlsPreflightError::DomainMismatch(domain)) if domain == "other.test"
    ));
    Ok(())
}

#[test]
fn rejects_mismatched_private_key() -> Result<(), Box<dyn std::error::Error>> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let directory = tempfile::tempdir()?;
    let tls = files(&directory, vec!["example.test".to_owned()])?;
    let other = generate_simple_self_signed(vec!["example.test".to_owned()])?;
    fs::write(&tls.key_file, other.key_pair.serialize_pem())?;
    assert!(matches!(
        preflight(&tls),
        Err(TlsPreflightError::KeyMismatch)
    ));
    Ok(())
}
