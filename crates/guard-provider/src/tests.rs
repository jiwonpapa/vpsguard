//! provider 단계·복구 회귀 테스트입니다.

use super::{ProviderBackend, ProviderError, ProviderSnapshot, ProviderStage, ProviderTransaction};

#[derive(Default)]
struct FakeBackend {
    proxy_verified: bool,
    origin_verified: bool,
    origin_lock_calls: usize,
    restore_calls: usize,
}

impl ProviderBackend for FakeBackend {
    fn snapshot(&mut self, record_name: &str) -> Result<ProviderSnapshot, ProviderError> {
        Ok(ProviderSnapshot {
            record_name: record_name.to_owned(),
            proxied: false,
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
    transaction.restore(&mut backend)?;
    assert_eq!(transaction.stage, ProviderStage::Restored);
    assert_eq!(backend.restore_calls, 1);
    Ok(())
}
