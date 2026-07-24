//! TLS reload bundle 원자 준비와 권한 회귀 테스트입니다.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use guard_core::config::CertificateConfig;
use rcgen::generate_simple_self_signed;

use super::{TlsReloadStageError, stage_tls_reload_bundle};

fn certificate_fixture(
    root: &std::path::Path,
    domain: &str,
) -> Result<CertificateConfig, Box<dyn std::error::Error>> {
    let generated = generate_simple_self_signed(vec![domain.to_owned()])?;
    let certificate = root.join("source-cert.pem");
    let key = root.join("source-key.pem");
    fs::write(&certificate, generated.cert.pem())?;
    fs::write(&key, generated.key_pair.serialize_pem())?;
    Ok(CertificateConfig {
        domains: vec![domain.to_owned()],
        cert_file: certificate,
        key_file: key,
        certbot_lineage: None,
    })
}

#[test]
fn stages_valid_bundle_with_runtime_owner_and_private_modes()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let runtime_root = temporary.path().join("runtime");
    fs::create_dir(&runtime_root)?;
    let source = certificate_fixture(temporary.path(), "example.test")?;

    let report = stage_tls_reload_bundle(&source, &runtime_root)?;

    assert_eq!(
        fs::read(&report.certificate_file)?,
        fs::read(&source.cert_file)?
    );
    assert_eq!(fs::read(&report.key_file)?, fs::read(&source.key_file)?);
    let root_metadata = fs::metadata(&runtime_root)?;
    for path in [&report.certificate_file, &report.key_file] {
        let metadata = fs::metadata(path)?;
        assert_eq!(metadata.uid(), root_metadata.uid());
        assert_eq!(metadata.gid(), root_metadata.gid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o440);
    }
    assert_eq!(
        fs::metadata(report.certificate_file.parent().ok_or("missing parent")?)?
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    Ok(())
}

#[test]
fn invalid_bundle_does_not_replace_previous_stage() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let runtime_root = temporary.path().join("runtime");
    fs::create_dir(&runtime_root)?;
    let first = certificate_fixture(temporary.path(), "example.test")?;
    let staged = stage_tls_reload_bundle(&first, &runtime_root)?;
    let certificate_before = fs::read(&staged.certificate_file)?;
    let key_before = fs::read(&staged.key_file)?;

    let invalid = certificate_fixture(temporary.path(), "other.test")?;
    let result = stage_tls_reload_bundle(
        &CertificateConfig {
            domains: vec!["example.test".to_owned()],
            ..invalid
        },
        &runtime_root,
    );

    assert!(matches!(result, Err(TlsReloadStageError::Certificate(_))));
    assert_eq!(fs::read(staged.certificate_file)?, certificate_before);
    assert_eq!(fs::read(staged.key_file)?, key_before);
    Ok(())
}
