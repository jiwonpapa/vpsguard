//! provider 단계·복구 회귀 테스트입니다.

use super::{
    ProviderBackend, ProviderError, ProviderRecordSnapshot, ProviderSnapshot, ProviderStage,
    ProviderTransaction,
};
use guard_core::config::DnsRecordType;

#[derive(Default)]
struct FakeBackend {
    proxy_verified: bool,
    origin_verified: bool,
    origin_lock_calls: usize,
    restore_calls: usize,
    restore_error: bool,
}

impl ProviderBackend for FakeBackend {
    fn snapshot(&mut self, record_name: &str) -> Result<ProviderSnapshot, ProviderError> {
        Ok(ProviderSnapshot {
            record_name: record_name.to_owned(),
            records: vec![ProviderRecordSnapshot {
                id: "11111111111111111111111111111111".to_owned(),
                name: record_name.to_owned(),
                record_type: DnsRecordType::A,
                proxied: false,
            }],
            origin_locked: false,
        })
    }

    fn request_proxy_enable(&mut self, _record_name: &str) -> Result<(), ProviderError> {
        Ok(())
    }

    fn verify_proxy_enabled(&mut self, _record_name: &str) -> Result<bool, ProviderError> {
        Ok(self.proxy_verified)
    }

    fn request_origin_lock(&mut self) -> Result<(), ProviderError> {
        self.origin_lock_calls += 1;
        Ok(())
    }

    fn verify_origin_lock(&mut self) -> Result<bool, ProviderError> {
        Ok(self.origin_verified)
    }

    fn restore(&mut self, _snapshot: &ProviderSnapshot) -> Result<(), ProviderError> {
        self.restore_calls += 1;
        if self.restore_error {
            return Err(ProviderError::Backend("RESTORE_FAILED".to_owned()));
        }
        Ok(())
    }
}

fn transaction() -> Result<ProviderTransaction, ProviderError> {
    ProviderTransaction::new(
        "action-1",
        "guard.example.com",
        &["guard.example.com".to_owned()],
    )
}

#[test]
fn never_locks_origin_before_proxy_verification() -> Result<(), ProviderError> {
    let mut backend = FakeBackend::default();
    let mut transaction = transaction()?;
    assert_eq!(
        transaction.enable(&mut backend),
        Err(ProviderError::ProxyNotVerified)
    );
    assert_eq!(backend.origin_lock_calls, 0);
    assert_eq!(transaction.stage, ProviderStage::ProxyRequested);
    assert_eq!(transaction.attempts, 3);
    assert_eq!(
        transaction.last_error.as_deref(),
        Some("PROXY_NOT_VERIFIED")
    );
    Ok(())
}

#[test]
fn exposes_single_steps_for_durable_checkpoints() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: true,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    assert_eq!(
        transaction.enable_step(&mut backend)?,
        ProviderStage::Snapshotted
    );
    assert_eq!(
        transaction.enable_step(&mut backend)?,
        ProviderStage::ProxyRequested
    );
    assert_eq!(backend.origin_lock_calls, 0);
    Ok(())
}

#[test]
fn completes_and_is_idempotent() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: true,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    transaction.enable(&mut backend)?;
    transaction.enable(&mut backend)?;
    assert_eq!(transaction.stage, ProviderStage::Complete);
    assert_eq!(backend.origin_lock_calls, 1);
    Ok(())
}

#[test]
fn restores_snapshot() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: true,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    transaction.enable(&mut backend)?;
    assert_eq!(
        transaction.restore_step(&mut backend)?,
        ProviderStage::RestoreRequested
    );
    assert_eq!(backend.restore_calls, 0);
    assert_eq!(
        transaction.restore_step(&mut backend)?,
        ProviderStage::Restored
    );
    assert_eq!(transaction.stage, ProviderStage::Restored);
    assert_eq!(backend.restore_calls, 1);
    Ok(())
}

#[test]
fn can_restore_after_partial_provider_progress() -> Result<(), ProviderError> {
    let mut backend = FakeBackend::default();
    let mut transaction = transaction()?;
    assert_eq!(
        transaction.enable_step(&mut backend)?,
        ProviderStage::Snapshotted
    );
    assert_eq!(
        transaction.enable_step(&mut backend)?,
        ProviderStage::ProxyRequested
    );
    assert_eq!(
        transaction.restore_step(&mut backend)?,
        ProviderStage::RestoreRequested
    );
    assert_eq!(
        transaction.restore_step(&mut backend)?,
        ProviderStage::Restored
    );
    assert_eq!(backend.restore_calls, 1);
    Ok(())
}

#[test]
fn rejects_record_outside_allowlist() {
    assert_eq!(
        ProviderTransaction::new(
            "action-2",
            "other.example.com",
            &["guard.example.com".to_owned()],
        ),
        Err(ProviderError::RecordNotAllowed(
            "other.example.com".to_owned()
        ))
    );
}

#[test]
fn records_origin_readback_failure() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: false,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    assert_eq!(
        transaction.enable(&mut backend),
        Err(ProviderError::OriginLockNotVerified)
    );
    assert_eq!(
        transaction.last_error.as_deref(),
        Some("ORIGIN_LOCK_NOT_VERIFIED")
    );
    Ok(())
}

#[test]
fn restore_wrapper_is_idempotent() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: true,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    transaction.enable(&mut backend)?;
    transaction.restore(&mut backend)?;
    transaction.restore(&mut backend)?;
    assert_eq!(transaction.stage, ProviderStage::Restored);
    assert_eq!(backend.restore_calls, 1);
    Ok(())
}

#[test]
fn restore_failures_keep_a_resumable_checkpoint() -> Result<(), ProviderError> {
    let mut backend = FakeBackend {
        proxy_verified: true,
        origin_verified: true,
        restore_error: true,
        ..FakeBackend::default()
    };
    let mut transaction = transaction()?;
    transaction.enable(&mut backend)?;
    assert_eq!(
        transaction.restore_step(&mut backend)?,
        ProviderStage::RestoreRequested
    );
    assert_eq!(
        transaction.restore_step(&mut backend),
        Err(ProviderError::Backend("RESTORE_FAILED".to_owned()))
    );
    assert_eq!(transaction.stage, ProviderStage::RestoreRequested);
    assert_eq!(
        transaction.last_error.as_deref(),
        Some("PROVIDER_BACKEND_FAILED")
    );
    assert!(transaction.enable_step(&mut backend).is_err());
    Ok(())
}

#[test]
fn restore_rejects_missing_or_incomplete_snapshot() -> Result<(), ProviderError> {
    let mut backend = FakeBackend::default();
    let mut incomplete = transaction()?;
    assert!(incomplete.restore_step(&mut backend).is_err());

    incomplete.stage = ProviderStage::Complete;
    incomplete.snapshot = None;
    assert_eq!(
        incomplete.restore_step(&mut backend),
        Err(ProviderError::MissingSnapshot)
    );
    Ok(())
}

#[test]
fn provider_errors_have_stable_codes() {
    let cases = [
        (
            ProviderError::RecordNotAllowed("record".to_owned()),
            "RECORD_NOT_ALLOWED",
        ),
        (ProviderError::SecretFile("mode"), "SECRET_FILE_INVALID"),
        (
            ProviderError::Configuration("zone"),
            "CONFIGURATION_INVALID",
        ),
        (ProviderError::AuthenticationFailed, "AUTHENTICATION_FAILED"),
        (ProviderError::PermissionDenied, "PERMISSION_DENIED"),
        (ProviderError::RateLimited, "RATE_LIMITED"),
        (ProviderError::Unavailable, "PROVIDER_UNAVAILABLE"),
        (ProviderError::TokenInactive, "TOKEN_INACTIVE"),
        (
            ProviderError::RecordMismatch("record".to_owned()),
            "RECORD_MISMATCH",
        ),
        (
            ProviderError::PartialRollbackFailed,
            "PARTIAL_ROLLBACK_FAILED",
        ),
        (ProviderError::ProxyNotVerified, "PROXY_NOT_VERIFIED"),
        (
            ProviderError::OriginLockNotVerified,
            "ORIGIN_LOCK_NOT_VERIFIED",
        ),
        (
            ProviderError::Backend("backend".to_owned()),
            "PROVIDER_BACKEND_FAILED",
        ),
        (ProviderError::MissingSnapshot, "MISSING_SNAPSHOT"),
    ];

    for (error, expected) in cases {
        assert_eq!(error.code(), expected);
    }
}
