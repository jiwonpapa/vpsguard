//! Hash 검증과 TTL을 갖는 versioned policy snapshot입니다.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::state::GuardMode;

const MAX_PROTECTION_REQUESTS_PER_MINUTE: u32 = 6_000;

/// route 단위 실행 규칙입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// 정규화된 route class입니다.
    pub route_class: String,
    /// 분당 요청 한도입니다.
    pub requests_per_minute: u32,
}

/// client 단위 TTL 규칙입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRule {
    /// 대상 IP입니다.
    pub client_ip: IpAddr,
    /// 실행할 판정입니다.
    pub action: crate::detection::Decision,
    /// 규칙 만료 시각입니다.
    pub expires_at: String,
    /// 근거 코드입니다.
    pub reason_codes: Vec<crate::detection::ReasonCode>,
}

/// 정책과 무관하게 유지되는 정적 안전 한도입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLimits {
    /// 일반 body 최대 크기입니다.
    pub max_body_bytes: u64,
    /// limiter cardinality 상한입니다.
    pub max_tracked_clients: usize,
}

/// 재시작 없이 hot policy로 조정하는 단계별 경로 제한입니다.
///
/// 수치가 작을수록 강한 제한입니다. 비상 단계가 로컬 단계보다 느슨해지거나 upload
/// 경로가 같은 단계의 strict 경로보다 느슨해지는 설정은 거부합니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionSettings {
    /// WATCH·RECOVERING의 strict 경로 분당 요청 한도입니다.
    pub watch_strict_requests_per_minute: u32,
    /// LOCAL_GUARD의 strict 경로 분당 요청 한도입니다.
    pub local_strict_requests_per_minute: u32,
    /// LOCAL_GUARD의 upload 경로 분당 요청 한도입니다.
    pub local_upload_requests_per_minute: u32,
    /// EMERGENCY_PROXY·RECOVERY_READY의 strict 경로 분당 요청 한도입니다.
    pub emergency_strict_requests_per_minute: u32,
    /// EMERGENCY_PROXY·RECOVERY_READY의 upload 경로 분당 요청 한도입니다.
    pub emergency_upload_requests_per_minute: u32,
}

impl Default for ProtectionSettings {
    fn default() -> Self {
        Self {
            watch_strict_requests_per_minute: 120,
            local_strict_requests_per_minute: 30,
            local_upload_requests_per_minute: 15,
            emergency_strict_requests_per_minute: 10,
            emergency_upload_requests_per_minute: 5,
        }
    }
}

/// 관리자 보호 제한값 검증 실패입니다.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ProtectionSettingsError {
    /// 분당 요청 한도가 지원 범위를 벗어났습니다.
    #[error("보호 제한값은 1..={MAX_PROTECTION_REQUESTS_PER_MINUTE} 범위여야 합니다: {0}")]
    OutOfRange(&'static str),
    /// 더 강한 단계 또는 upload 경로가 앞 단계보다 느슨합니다.
    #[error("보호 단계별 제한 강도가 올바르지 않습니다: {0}")]
    StageOrder(&'static str),
}

impl ProtectionSettings {
    /// 각 값의 범위와 단계별 단조 강화 관계를 검증합니다.
    ///
    /// # Errors
    ///
    /// 범위를 벗어나거나 비상·upload 제한이 앞 단계보다 느슨하면 오류를 반환합니다.
    pub fn validate(self) -> Result<(), ProtectionSettingsError> {
        for (name, value) in [
            (
                "watch_strict_requests_per_minute",
                self.watch_strict_requests_per_minute,
            ),
            (
                "local_strict_requests_per_minute",
                self.local_strict_requests_per_minute,
            ),
            (
                "local_upload_requests_per_minute",
                self.local_upload_requests_per_minute,
            ),
            (
                "emergency_strict_requests_per_minute",
                self.emergency_strict_requests_per_minute,
            ),
            (
                "emergency_upload_requests_per_minute",
                self.emergency_upload_requests_per_minute,
            ),
        ] {
            if !(1..=MAX_PROTECTION_REQUESTS_PER_MINUTE).contains(&value) {
                return Err(ProtectionSettingsError::OutOfRange(name));
            }
        }
        if self.local_strict_requests_per_minute > self.watch_strict_requests_per_minute {
            return Err(ProtectionSettingsError::StageOrder(
                "local_strict_requests_per_minute",
            ));
        }
        if self.emergency_strict_requests_per_minute > self.local_strict_requests_per_minute {
            return Err(ProtectionSettingsError::StageOrder(
                "emergency_strict_requests_per_minute",
            ));
        }
        if self.local_upload_requests_per_minute > self.local_strict_requests_per_minute {
            return Err(ProtectionSettingsError::StageOrder(
                "local_upload_requests_per_minute",
            ));
        }
        if self.emergency_upload_requests_per_minute > self.local_upload_requests_per_minute {
            return Err(ProtectionSettingsError::StageOrder(
                "emergency_upload_requests_per_minute",
            ));
        }
        if self.emergency_upload_requests_per_minute > self.emergency_strict_requests_per_minute {
            return Err(ProtectionSettingsError::StageOrder(
                "emergency_upload_requests_per_minute",
            ));
        }
        Ok(())
    }

    /// 현재 방어 mode에 적용할 bounded route 규칙을 생성합니다.
    #[must_use]
    pub fn route_rules(self, mode: GuardMode) -> Vec<RouteRule> {
        match mode {
            GuardMode::Normal | GuardMode::ManualHold => Vec::new(),
            GuardMode::Watch | GuardMode::Recovering => vec![RouteRule {
                route_class: "strict".to_owned(),
                requests_per_minute: self.watch_strict_requests_per_minute,
            }],
            GuardMode::LocalGuard => vec![
                RouteRule {
                    route_class: "strict".to_owned(),
                    requests_per_minute: self.local_strict_requests_per_minute,
                },
                RouteRule {
                    route_class: "upload".to_owned(),
                    requests_per_minute: self.local_upload_requests_per_minute,
                },
            ],
            GuardMode::EmergencyProxy | GuardMode::RecoveryReady => vec![
                RouteRule {
                    route_class: "strict".to_owned(),
                    requests_per_minute: self.emergency_strict_requests_per_minute,
                },
                RouteRule {
                    route_class: "upload".to_owned(),
                    requests_per_minute: self.emergency_upload_requests_per_minute,
                },
            ],
        }
    }
}

/// edge에 원자 적용되는 정책 snapshot입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshot {
    /// 정책 schema 버전입니다.
    pub schema_version: u32,
    /// 단조 증가 정책 버전입니다.
    pub policy_version: u64,
    /// 생성 시각입니다.
    pub generated_at: String,
    /// 자동 규칙 만료 시각입니다.
    pub expires_at: String,
    /// 정책 방어 모드입니다.
    pub mode: GuardMode,
    /// route 규칙입니다.
    pub route_rules: Vec<RouteRule>,
    /// client TTL 규칙입니다.
    pub client_rules: Vec<ClientRule>,
    /// 정적 안전 한도입니다.
    pub static_limits: StaticLimits,
    /// 본문 SHA-256입니다. hash 계산 시 이 필드는 빈 문자열입니다.
    pub content_sha256: String,
}

/// 정책 검증 실패입니다.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// 미래 schema입니다.
    #[error("지원하지 않는 정책 schema입니다: {0}")]
    UnsupportedSchema(u32),
    /// JSON 직렬화가 실패했습니다.
    #[error("정책 hash 직렬화에 실패했습니다: {0}")]
    Serialize(String),
    /// 저장된 hash와 계산값이 다릅니다.
    #[error("정책 content hash가 일치하지 않습니다")]
    HashMismatch,
    /// RFC3339 시각이 아닙니다.
    #[error("정책 시각 형식이 잘못됐습니다: {0}")]
    InvalidTime(String),
    /// 자동 규칙이 만료됐습니다.
    #[error("정책이 만료됐습니다")]
    Expired,
    /// 안전 한도가 0입니다.
    #[error("정책 안전 한도는 0일 수 없습니다: {0}")]
    ZeroLimit(&'static str),
    /// 관리자 보호 제한이 범위 또는 단계 관계를 위반했습니다.
    #[error(transparent)]
    ProtectionSettings(#[from] ProtectionSettingsError),
}

impl PolicySnapshot {
    /// 현재 본문을 기준으로 SHA-256을 계산합니다.
    ///
    /// # Errors
    ///
    /// JSON 직렬화 실패를 반환합니다.
    pub fn calculate_hash(&self) -> Result<String, PolicyError> {
        let mut canonical = self.clone();
        canonical.content_sha256.clear();
        let bytes = serde_json::to_vec(&canonical)
            .map_err(|error| PolicyError::Serialize(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// 계산한 hash를 snapshot에 설정합니다.
    ///
    /// # Errors
    ///
    /// JSON 직렬화 실패를 반환합니다.
    pub fn seal(mut self) -> Result<Self, PolicyError> {
        self.content_sha256 = self.calculate_hash()?;
        Ok(self)
    }

    /// schema, hash, 범위와 만료를 검증합니다.
    ///
    /// # Errors
    ///
    /// 미래 schema, hash 불일치, 시각 오류, 만료 또는 0 한도를 반환합니다.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), PolicyError> {
        if self.schema_version != 1 {
            return Err(PolicyError::UnsupportedSchema(self.schema_version));
        }
        if self.static_limits.max_body_bytes == 0 {
            return Err(PolicyError::ZeroLimit("max_body_bytes"));
        }
        if self.static_limits.max_tracked_clients == 0 {
            return Err(PolicyError::ZeroLimit("max_tracked_clients"));
        }
        if self.calculate_hash()? != self.content_sha256 {
            return Err(PolicyError::HashMismatch);
        }
        let expires = OffsetDateTime::parse(&self.expires_at, &Rfc3339)
            .map_err(|_| PolicyError::InvalidTime(self.expires_at.clone()))?;
        OffsetDateTime::parse(&self.generated_at, &Rfc3339)
            .map_err(|_| PolicyError::InvalidTime(self.generated_at.clone()))?;
        if expires <= now {
            return Err(PolicyError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
