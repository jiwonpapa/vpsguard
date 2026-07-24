//! Edge startup parsing and crypto-provider regression tests.

use std::fs;

use super::{
    EdgeStartupError, GRACE_PERIOD_SECONDS, GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS, UPGRADE_SOCKET,
    install_crypto_provider, load_runtime, server_configuration,
};

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

#[test]
fn pingora_upgrade_uses_private_runtime_socket_and_bounded_drain() {
    let configuration = server_configuration();

    assert_eq!(configuration.upgrade_sock, UPGRADE_SOCKET);
    assert!(configuration.upgrade_sock.starts_with("/run/vps-guard/"));
    assert_eq!(
        configuration.grace_period_seconds,
        Some(GRACE_PERIOD_SECONDS)
    );
    assert_eq!(
        configuration.graceful_shutdown_timeout_seconds,
        Some(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS)
    );
    assert_eq!(
        configuration.upgrade_sock_connect_accept_max_retries,
        Some(10)
    );
}
