//! Cloudflare와 VPS provider의 검증 가능한 단계별 transaction을 소유합니다.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// provider read-back snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshot {
    /// 대상 DNS record입니다.
    pub record_name: String,
    /// 이전 proxied 상태입니다.
    pub proxied: bool,
    /// 이전 원본 보호 상태입니다.
    pub origin_locked: bool,
}

/// 비상 전환 단계입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStage {
    /// 시작 전입니다.
    Pending,
    /// snapshot을 확보했습니다.
    Snapshotted,
    /// proxy enable을 요청했습니다.
    ProxyRequested,
    /// 외부 HTTPS 경유가 검증됐습니다.
    ProxyVerified,
    /// 원본 보호를 요청했습니다.
    OriginLockRequested,
    /// 원본 보호 read-back을 검증했습니다.
    Complete,
    /// 이전 snapshot으로 복구했습니다.
    Restored,
}

/// 재개 가능한 provider transaction 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTransaction {
    /// idempotency key입니다.
    pub idempotency_key: String,
    /// allowlist 검증 대상 record입니다.
    pub record_name: String,
    /// 현재 단계입니다.
    pub stage: ProviderStage,
    /// rollback snapshot입니다.
    pub snapshot: Option<ProviderSnapshot>,
    /// 마지막 구조화 오류 코드입니다.
    pub last_error: Option<String>,
}

/// provider 외부 작업의 최소 adapter 계약입니다.
pub trait ProviderBackend {
    /// 현재 실제 상태를 읽습니다.
    fn snapshot(&mut self, record_name: &str) -> Result<ProviderSnapshot, ProviderError>;
    /// DNS proxy를 활성화합니다.
    fn request_proxy_enable(&mut self, record_name: &str) -> Result<(), ProviderError>;
    /// 외부 HTTPS 경유를 검증합니다.
    fn verify_proxy_enabled(&mut self, record_name: &str) -> Result<bool, ProviderError>;
    /// 원본 80/443 보호를 요청합니다. SSH는 adapter 계약상 변경할 수 없습니다.
    fn request_origin_lock(&mut self) -> Result<(), ProviderError>;
    /// 원본 보호를 read-back합니다.
    fn verify_origin_lock(&mut self) -> Result<bool, ProviderError>;
    /// 이전 snapshot을 복구합니다.
    fn restore(&mut self, snapshot: &ProviderSnapshot) -> Result<(), ProviderError>;
}

/// provider transaction 실패입니다.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// record가 설정 allowlist에 없습니다.
    #[error("provider record allowlist 위반: {0}")]
    RecordNotAllowed(String),
    /// proxy API 성공 후 외부 경유가 검증되지 않았습니다.
    #[error("provider proxy 경유를 검증하지 못했습니다")]
    ProxyNotVerified,
    /// 원본 보호 read-back이 실패했습니다.
    #[error("provider 원본 보호를 검증하지 못했습니다")]
    OriginLockNotVerified,
    /// adapter 작업 실패입니다.
    #[error("provider backend 실패: {0}")]
    Backend(String),
    /// rollback snapshot이 없습니다.
    #[error("provider rollback snapshot이 없습니다")]
    MissingSnapshot,
}

impl ProviderTransaction {
    /// allowlist 검증된 새 transaction을 생성합니다.
    ///
    /// # Errors
    ///
    /// record가 allowlist에 없으면 거부합니다.
    pub fn new(
        idempotency_key: impl Into<String>,
        record_name: impl Into<String>,
        allowed_records: &[String],
    ) -> Result<Self, ProviderError> {
        let record_name = record_name.into();
        if !allowed_records
            .iter()
            .any(|allowed| allowed == &record_name)
        {
            return Err(ProviderError::RecordNotAllowed(record_name));
        }
        Ok(Self {
            idempotency_key: idempotency_key.into(),
            record_name,
            stage: ProviderStage::Pending,
            snapshot: None,
            last_error: None,
        })
    }

    /// API success가 아니라 read-back 순서로 비상 보호를 완료합니다.
    ///
    /// # Errors
    ///
    /// backend 실패 또는 검증 실패를 반환하며 proxy 검증 전에는 origin lock을 호출하지 않습니다.
    pub fn enable<B: ProviderBackend>(&mut self, backend: &mut B) -> Result<(), ProviderError> {
        if self.stage == ProviderStage::Complete {
            return Ok(());
        }
        if self.stage == ProviderStage::Pending {
            self.snapshot = Some(backend.snapshot(&self.record_name)?);
            self.stage = ProviderStage::Snapshotted;
        }
        if self.stage == ProviderStage::Snapshotted {
            backend.request_proxy_enable(&self.record_name)?;
            self.stage = ProviderStage::ProxyRequested;
        }
        if self.stage == ProviderStage::ProxyRequested {
            if !backend.verify_proxy_enabled(&self.record_name)? {
                self.last_error = Some("PROXY_NOT_VERIFIED".to_owned());
                return Err(ProviderError::ProxyNotVerified);
            }
            self.stage = ProviderStage::ProxyVerified;
        }
        if self.stage == ProviderStage::ProxyVerified {
            backend.request_origin_lock()?;
            self.stage = ProviderStage::OriginLockRequested;
        }
        if self.stage == ProviderStage::OriginLockRequested {
            if !backend.verify_origin_lock()? {
                self.last_error = Some("ORIGIN_LOCK_NOT_VERIFIED".to_owned());
                return Err(ProviderError::OriginLockNotVerified);
            }
            self.stage = ProviderStage::Complete;
            self.last_error = None;
        }
        Ok(())
    }

    /// snapshot 기반으로 이전 상태를 복구합니다.
    ///
    /// # Errors
    ///
    /// snapshot 부재 또는 backend 실패를 반환합니다.
    pub fn restore<B: ProviderBackend>(&mut self, backend: &mut B) -> Result<(), ProviderError> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(ProviderError::MissingSnapshot)?;
        backend.restore(snapshot)?;
        self.stage = ProviderStage::Restored;
        self.last_error = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
