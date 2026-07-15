//! Cloudflare와 VPS provider의 검증 가능한 단계별 transaction을 소유합니다.

use guard_core::config::DnsRecordType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod cloudflare;

/// provider read-back snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSnapshot {
    /// 대상 DNS record입니다.
    pub record_name: String,
    /// 명시적 allowlist record별 이전 상태입니다.
    pub records: Vec<ProviderRecordSnapshot>,
    /// 이전 원본 보호 상태입니다.
    pub origin_locked: bool,
}

/// provider rollback에 필요한 단일 DNS record 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecordSnapshot {
    /// Cloudflare DNS record ID입니다.
    pub id: String,
    /// 완전한 DNS record hostname입니다.
    pub name: String,
    /// DNS record type입니다.
    pub record_type: DnsRecordType,
    /// snapshot 시점의 proxy 상태입니다.
    pub proxied: bool,
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
    /// 저장된 snapshot 복구를 실행하기 직전 checkpoint입니다.
    RestoreRequested,
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
    /// 외부 adapter 단계 실행 시도 횟수입니다.
    #[serde(default)]
    pub attempts: u32,
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
    /// 비밀 파일 경계가 잘못됐습니다.
    #[error("provider secret 파일이 안전하지 않습니다: {0}")]
    SecretFile(&'static str),
    /// provider 설정이 안전 계약을 충족하지 않습니다.
    #[error("provider 설정이 잘못됐습니다: {0}")]
    Configuration(&'static str),
    /// API token 인증이 실패했습니다.
    #[error("provider token 인증이 실패했습니다")]
    AuthenticationFailed,
    /// API token에 대상 resource 권한이 없습니다.
    #[error("provider token 권한이 부족합니다")]
    PermissionDenied,
    /// provider API 호출 한도를 초과했습니다.
    #[error("provider API 호출 한도를 초과했습니다")]
    RateLimited,
    /// provider API가 일시적으로 응답할 수 없습니다.
    #[error("provider API를 사용할 수 없습니다")]
    Unavailable,
    /// token이 비활성·만료 상태입니다.
    #[error("provider token이 활성 상태가 아닙니다")]
    TokenInactive,
    /// API 응답 record가 설정 allowlist와 다릅니다.
    #[error("provider record 식별 정보가 설정과 다릅니다: {0}")]
    RecordMismatch(String),
    /// 여러 record 변경 중 실패했고 즉시 rollback도 완료하지 못했습니다.
    #[error("provider 일부 변경의 즉시 rollback이 실패했습니다")]
    PartialRollbackFailed,
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

impl ProviderError {
    /// API·event·UI에서 비밀값 없이 사용할 안정 오류 코드입니다.
    #[must_use]
    pub fn code(&self) -> &'static str {
        provider_error_code(self)
    }
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
            attempts: 0,
        })
    }

    /// API success가 아니라 read-back 순서로 비상 보호를 완료합니다.
    ///
    /// # Errors
    ///
    /// backend 실패 또는 검증 실패를 반환하며 proxy 검증 전에는 origin lock을 호출하지 않습니다.
    pub fn enable<B: ProviderBackend>(&mut self, backend: &mut B) -> Result<(), ProviderError> {
        loop {
            if self.enable_step(backend)? == ProviderStage::Complete {
                return Ok(());
            }
        }
    }

    /// 외부 side effect를 한 단계만 실행해 호출자가 즉시 checkpoint할 수 있게 합니다.
    ///
    /// # Errors
    ///
    /// backend 실패, read-back 불일치 또는 복구 완료 transaction 재사용을 반환합니다.
    pub fn enable_step<B: ProviderBackend>(
        &mut self,
        backend: &mut B,
    ) -> Result<ProviderStage, ProviderError> {
        if self.stage == ProviderStage::Complete {
            return Ok(self.stage);
        }
        if matches!(
            self.stage,
            ProviderStage::RestoreRequested | ProviderStage::Restored
        ) {
            return Err(ProviderError::Backend(
                "RESTORE_TRANSACTION_CANNOT_ENABLE".to_owned(),
            ));
        }
        self.attempts = self.attempts.saturating_add(1);
        let result = (|| {
            match self.stage {
                ProviderStage::Pending => {
                    self.snapshot = Some(backend.snapshot(&self.record_name)?);
                    self.stage = ProviderStage::Snapshotted;
                }
                ProviderStage::Snapshotted => {
                    backend.request_proxy_enable(&self.record_name)?;
                    self.stage = ProviderStage::ProxyRequested;
                }
                ProviderStage::ProxyRequested => {
                    if !backend.verify_proxy_enabled(&self.record_name)? {
                        return Err(ProviderError::ProxyNotVerified);
                    }
                    self.stage = ProviderStage::ProxyVerified;
                }
                ProviderStage::ProxyVerified => {
                    backend.request_origin_lock()?;
                    self.stage = ProviderStage::OriginLockRequested;
                }
                ProviderStage::OriginLockRequested => {
                    if !backend.verify_origin_lock()? {
                        return Err(ProviderError::OriginLockNotVerified);
                    }
                    self.stage = ProviderStage::Complete;
                }
                ProviderStage::Complete
                | ProviderStage::RestoreRequested
                | ProviderStage::Restored => {
                    return Err(ProviderError::Backend(
                        "INVALID_PROVIDER_ENABLE_STAGE".to_owned(),
                    ));
                }
            }
            Ok(self.stage)
        })();
        match &result {
            Ok(_) => self.last_error = None,
            Err(error) => self.last_error = Some(provider_error_code(error).to_owned()),
        }
        result
    }

    /// snapshot 기반으로 이전 상태를 복구합니다.
    ///
    /// # Errors
    ///
    /// snapshot 부재 또는 backend 실패를 반환합니다.
    pub fn restore<B: ProviderBackend>(&mut self, backend: &mut B) -> Result<(), ProviderError> {
        loop {
            if self.restore_step(backend)? == ProviderStage::Restored {
                return Ok(());
            }
        }
    }

    /// 복구 의도를 먼저 checkpoint한 뒤 snapshot 복구와 read-back을 실행합니다.
    ///
    /// # Errors
    ///
    /// 완료되지 않은 transaction, snapshot 부재 또는 backend 복구 실패를 반환합니다.
    pub fn restore_step<B: ProviderBackend>(
        &mut self,
        backend: &mut B,
    ) -> Result<ProviderStage, ProviderError> {
        match self.stage {
            ProviderStage::Restored => {}
            ProviderStage::RestoreRequested => {
                self.attempts = self.attempts.saturating_add(1);
                let snapshot = self
                    .snapshot
                    .as_ref()
                    .ok_or(ProviderError::MissingSnapshot)?;
                if let Err(error) = backend.restore(snapshot) {
                    self.last_error = Some(provider_error_code(&error).to_owned());
                    return Err(error);
                }
                self.stage = ProviderStage::Restored;
                self.last_error = None;
            }
            ProviderStage::Pending => {
                return Err(ProviderError::Backend(
                    "PROVIDER_TRANSACTION_NOT_STARTED".to_owned(),
                ));
            }
            ProviderStage::Snapshotted
            | ProviderStage::ProxyRequested
            | ProviderStage::ProxyVerified
            | ProviderStage::OriginLockRequested
            | ProviderStage::Complete => {
                if self.snapshot.is_none() {
                    return Err(ProviderError::MissingSnapshot);
                }
                self.stage = ProviderStage::RestoreRequested;
                self.last_error = None;
            }
        }
        Ok(self.stage)
    }
}

fn provider_error_code(error: &ProviderError) -> &'static str {
    match error {
        ProviderError::RecordNotAllowed(_) => "RECORD_NOT_ALLOWED",
        ProviderError::SecretFile(_) => "SECRET_FILE_INVALID",
        ProviderError::Configuration(_) => "CONFIGURATION_INVALID",
        ProviderError::AuthenticationFailed => "AUTHENTICATION_FAILED",
        ProviderError::PermissionDenied => "PERMISSION_DENIED",
        ProviderError::RateLimited => "RATE_LIMITED",
        ProviderError::Unavailable => "PROVIDER_UNAVAILABLE",
        ProviderError::TokenInactive => "TOKEN_INACTIVE",
        ProviderError::RecordMismatch(_) => "RECORD_MISMATCH",
        ProviderError::PartialRollbackFailed => "PARTIAL_ROLLBACK_FAILED",
        ProviderError::ProxyNotVerified => "PROXY_NOT_VERIFIED",
        ProviderError::OriginLockNotVerified => "ORIGIN_LOCK_NOT_VERIFIED",
        ProviderError::Backend(_) => "PROVIDER_BACKEND_FAILED",
        ProviderError::MissingSnapshot => "MISSING_SNAPSHOT",
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
