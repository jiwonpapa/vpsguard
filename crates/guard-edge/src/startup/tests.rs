//! Edge startup parsing and crypto-provider regression tests.

use std::fs;

use super::{EdgeStartupError, install_crypto_provider, load_runtime};

#[test]
fn startup_reports_missing_and_invalid_configuration() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let missing = temporary.path().join("missing.toml");
    assert!(matches!(
        load_runtime(&missing),
        Err(EdgeStartupError::ReadConfig(_))
    ));

    let invalid = temporary.path().join("invalid.toml");
    fs::write(&invalid, "schema_version = 999\n")?;
    assert!(matches!(
        load_runtime(&invalid),
        Err(EdgeStartupError::Config(_))
    ));
    Ok(())
}

#[test]
fn crypto_provider_installation_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    install_crypto_provider()?;
    install_crypto_provider()?;
    Ok(())
}
