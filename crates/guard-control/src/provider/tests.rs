//! Provider controller configuration and stable-stage regression tests.

use guard_core::GuardConfig;
use guard_provider::ProviderStage;

use super::{ProviderController, activation_stage_pending, provider_state_path, stage_name};

fn smoke_config() -> Result<GuardConfig, guard_core::ConfigError> {
    GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))
}

#[test]
fn disabled_provider_does_not_build_external_adapters() -> Result<(), Box<dyn std::error::Error>> {
    let config = smoke_config()?;
    assert!(!config.cloudflare.enabled);
    assert!(ProviderController::from_config(&config)?.is_none());
    Ok(())
}

#[test]
fn provider_stage_names_are_stable() {
    let expected = [
        (ProviderStage::Pending, "pending"),
        (ProviderStage::Snapshotted, "snapshotted"),
        (ProviderStage::ProxyRequested, "proxy_requested"),
        (ProviderStage::ProxyVerified, "proxy_verified"),
        (ProviderStage::ProxyDrain, "proxy_drain"),
        (ProviderStage::OriginLockRequested, "origin_lock_requested"),
        (ProviderStage::Complete, "complete"),
        (ProviderStage::RestoreRequested, "restore_requested"),
        (ProviderStage::Restored, "restored"),
    ];
    for (stage, name) in expected {
        assert_eq!(stage_name(stage), name);
    }
}

#[test]
fn incomplete_activation_stages_are_resumable() {
    for stage in [
        ProviderStage::Snapshotted,
        ProviderStage::ProxyRequested,
        ProviderStage::ProxyVerified,
        ProviderStage::ProxyDrain,
        ProviderStage::OriginLockRequested,
    ] {
        assert!(activation_stage_pending(stage));
    }
    for stage in [
        ProviderStage::Pending,
        ProviderStage::Complete,
        ProviderStage::RestoreRequested,
        ProviderStage::Restored,
    ] {
        assert!(!activation_stage_pending(stage));
    }
}

#[test]
fn provider_ledger_is_sibling_of_the_control_database() -> Result<(), Box<dyn std::error::Error>> {
    let config = smoke_config()?;
    let mut expected = config.storage.database_path.clone();
    expected.set_file_name("provider-transaction.json");
    assert_eq!(provider_state_path(&config), expected);
    Ok(())
}
