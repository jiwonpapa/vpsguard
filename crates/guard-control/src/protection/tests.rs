//! 관리자 보호 설정의 plan, idempotency, stale 거부와 재시작 복원 회귀입니다.

use guard_core::policy::ProtectionSettings;
use guard_core::{GuardMode, GuardState, PolicySnapshot};
use guard_system::AtomicJsonStore;

use super::{
    CurrentProtection, PersistedProtection, ProtectionPolicyError, ProtectionPolicyManager,
};

#[tokio::test]
async fn plan_apply_and_duplicate_operation_are_read_back_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    let candidate = ProtectionSettings {
        local_strict_requests_per_minute: 29,
        ..ProtectionSettings::default()
    };
    let plan = manager.plan(candidate)?;

    assert_eq!(plan.current_policy_version, 0);
    assert_eq!(plan.next_policy_version, 1);
    assert_eq!(plan.changes.len(), 1);
    let applied = manager
        .apply(
            "operation-1",
            &plan.current_fingerprint,
            &plan.plan_hash,
            candidate,
            GuardMode::LocalGuard,
        )
        .await?;
    assert!(applied.applied);
    assert_eq!(applied.snapshot.policy_version, 1);

    let policy = AtomicJsonStore::<PolicySnapshot>::new(path.clone()).read()?;
    assert_eq!(policy.policy_version, 1);
    assert_eq!(policy.route_rules[0].requests_per_minute, 29);
    assert!(!std::fs::read_to_string(&path)?.contains("protection_settings"));
    let metadata =
        AtomicJsonStore::<PersistedProtection>::new(path.with_extension("settings.json")).read()?;
    assert_eq!(metadata.settings, candidate);

    let duplicate = manager
        .apply(
            "operation-1",
            &plan.current_fingerprint,
            &plan.plan_hash,
            candidate,
            GuardMode::LocalGuard,
        )
        .await?;
    assert!(!duplicate.applied);
    assert_eq!(duplicate.snapshot.policy_version, 1);
    Ok(())
}

#[tokio::test]
async fn apply_rejects_a_stale_plan_and_conflicting_idempotency_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let manager = ProtectionPolicyManager::load(
        directory.path().join("policy.json"),
        0,
        GuardMode::Normal,
        1_048_576,
        10_000,
    )?;
    let first = ProtectionSettings {
        local_strict_requests_per_minute: 29,
        ..ProtectionSettings::default()
    };
    let first_plan = manager.plan(first)?;
    let stale = ProtectionSettings {
        local_strict_requests_per_minute: 28,
        ..ProtectionSettings::default()
    };
    let stale_plan = manager.plan(stale)?;

    manager
        .apply(
            "operation-1",
            &first_plan.current_fingerprint,
            &first_plan.plan_hash,
            first,
            GuardMode::LocalGuard,
        )
        .await?;
    assert!(matches!(
        manager
            .apply(
                "operation-2",
                &stale_plan.current_fingerprint,
                &stale_plan.plan_hash,
                stale,
                GuardMode::LocalGuard,
            )
            .await,
        Err(ProtectionPolicyError::StalePlan)
    ));
    assert!(matches!(
        manager
            .apply(
                "operation-1",
                &first_plan.current_fingerprint,
                &stale_plan.plan_hash,
                stale,
                GuardMode::LocalGuard,
            )
            .await,
        Err(ProtectionPolicyError::IdempotencyConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn manager_recovers_settings_and_keeps_them_across_mode_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    let candidate = ProtectionSettings {
        emergency_upload_requests_per_minute: 4,
        ..ProtectionSettings::default()
    };
    let plan = manager.plan(candidate)?;
    manager
        .apply(
            "operation-1",
            &plan.current_fingerprint,
            &plan.plan_hash,
            candidate,
            GuardMode::EmergencyProxy,
        )
        .await?;
    drop(manager);

    let recovered = ProtectionPolicyManager::load(path, 0, GuardMode::Normal, 1_048_576, 10_000)?;
    assert_eq!(recovered.snapshot()?.settings, candidate);
    assert_eq!(recovered.snapshot()?.policy_version, 1);

    let mut state = GuardState::normal("2026-07-24T00:00:00Z");
    state.current_mode = GuardMode::Watch;
    let refreshed = recovered.write_for_state(state).await?;
    assert_eq!(refreshed.policy_version, 2);
    assert_eq!(recovered.snapshot()?.settings, candidate);
    Ok(())
}

#[tokio::test]
async fn manager_rejects_missing_or_older_policy_than_durable_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    assert!(matches!(
        ProtectionPolicyManager::load(path.clone(), 1, GuardMode::Normal, 1_048_576, 10_000),
        Err(ProtectionPolicyError::MissingPolicy(1))
    ));

    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    let mut state = GuardState::normal("2026-07-24T00:00:00Z");
    state.current_mode = GuardMode::Watch;
    manager.write_for_state(state).await?;
    drop(manager);

    assert!(matches!(
        ProtectionPolicyManager::load(path, 2, GuardMode::Normal, 1_048_576, 10_000),
        Err(ProtectionPolicyError::StateVersionAhead {
            state_version: 2,
            file_version: 1
        })
    ));
    Ok(())
}

#[tokio::test]
async fn administrator_apply_and_mode_refresh_cannot_lose_settings_or_version()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    let candidate = ProtectionSettings {
        local_strict_requests_per_minute: 29,
        ..ProtectionSettings::default()
    };
    let plan = manager.plan(candidate)?;
    let mut state = GuardState::normal("2026-07-24T00:00:00Z");
    state.current_mode = GuardMode::Watch;

    let (applied, refreshed) = tokio::join!(
        manager.apply(
            "operation-concurrent",
            &plan.current_fingerprint,
            &plan.plan_hash,
            candidate,
            GuardMode::LocalGuard,
        ),
        manager.write_for_state(state),
    );
    applied?;
    refreshed?;

    let snapshot = manager.snapshot()?;
    assert_eq!(snapshot.settings, candidate);
    assert_eq!(snapshot.policy_version, 2);
    let policy = AtomicJsonStore::<PolicySnapshot>::new(path.clone()).read()?;
    assert_eq!(policy.policy_version, 2);
    assert_eq!(policy.route_rules, candidate.route_rules(policy.mode));
    let metadata =
        AtomicJsonStore::<PersistedProtection>::new(path.with_extension("settings.json")).read()?;
    assert_eq!(metadata.settings, candidate);
    Ok(())
}

#[tokio::test]
async fn restart_completes_metadata_first_transaction_without_changing_edge_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    let mut state = GuardState::normal("2026-07-24T00:00:00Z");
    state.current_mode = GuardMode::Watch;
    manager.write_for_state(state).await?;
    drop(manager);

    let candidate = ProtectionSettings {
        local_strict_requests_per_minute: 29,
        ..ProtectionSettings::default()
    };
    AtomicJsonStore::<PersistedProtection>::new(path.with_extension("settings.json")).write(
        &PersistedProtection::new(CurrentProtection {
            settings: candidate,
            policy_version: 2,
        })?,
    )?;

    let recovered =
        ProtectionPolicyManager::load(path.clone(), 1, GuardMode::LocalGuard, 1_048_576, 10_000)?;
    assert_eq!(recovered.snapshot()?.settings, candidate);
    assert_eq!(recovered.snapshot()?.policy_version, 2);
    let policy = AtomicJsonStore::<PolicySnapshot>::new(path.clone()).read()?;
    assert_eq!(policy.policy_version, 2);
    assert_eq!(
        policy.route_rules,
        candidate.route_rules(GuardMode::LocalGuard)
    );
    assert!(!std::fs::read_to_string(path)?.contains("protection_settings"));
    Ok(())
}

#[test]
fn tampered_protection_metadata_is_rejected_before_policy_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("policy.json");
    let manager =
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000)?;
    drop(manager);
    let metadata_store =
        AtomicJsonStore::<PersistedProtection>::new(path.with_extension("settings.json"));
    let mut metadata = metadata_store.read()?;
    metadata.settings.local_strict_requests_per_minute = 29;
    metadata_store.write(&metadata)?;

    assert!(matches!(
        ProtectionPolicyManager::load(path.clone(), 0, GuardMode::Normal, 1_048_576, 10_000),
        Err(ProtectionPolicyError::MetadataHashMismatch)
    ));
    assert!(!path.exists());
    Ok(())
}
