//! 방어 모드와 히스테리시스 상태 전이 계약입니다.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::detection::Assessment;

/// VPSGuard 방어 모드입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardMode {
    /// 정상 관찰 상태입니다.
    Normal,
    /// 이상 신호를 상세 관찰합니다.
    Watch,
    /// 로컬 제한이 적용된 상태입니다.
    LocalGuard,
    /// 외부 비상 보호가 필요한 상태입니다.
    EmergencyProxy,
    /// 안정 구간을 확인하며 제한을 해제합니다.
    Recovering,
    /// 관리자가 자동 전이를 고정했습니다.
    ManualHold,
}

/// 영속화되는 최소 제어 상태입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardState {
    /// 상태 schema 버전입니다.
    pub schema_version: u32,
    /// 현재 방어 모드입니다.
    pub current_mode: GuardMode,
    /// 자동 전이 고정 여부입니다.
    pub manual_hold: bool,
    /// 마지막 적용 정책 버전입니다.
    pub policy_version: u64,
    /// 마지막 전이 시각 RFC3339 문자열입니다.
    pub last_transition_at: String,
    /// 마지막 정상 시각 RFC3339 문자열입니다.
    pub last_healthy_at: String,
    /// 현재 사건 식별자입니다.
    pub active_incident_id: Option<String>,
    /// Nginx 직접 연결 bypass 여부입니다.
    pub bypass_enabled: bool,
    /// 연속 위험 window 수입니다.
    pub breach_windows: u8,
    /// 연속 안정 window 수입니다.
    pub stable_windows: u8,
}

/// 한 상태 전이에 필요한 입력입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionInput {
    /// 현재 탐지 판정입니다.
    pub assessment: Assessment,
    /// 분산 공격이 확인됐는지 여부입니다.
    pub distributed_pressure: bool,
    /// 외부 보호가 실제 적용됐는지 여부입니다.
    pub provider_verified: bool,
    /// 판정 시각 RFC3339 문자열입니다.
    pub occurred_at: String,
}

/// 상태 계약 검증 실패입니다.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    /// 미래 schema는 처리하지 않습니다.
    #[error("지원하지 않는 상태 schema입니다: {0}")]
    UnsupportedSchema(u32),
    /// 수동 고정 필드와 모드가 일치하지 않습니다.
    #[error("manual_hold와 current_mode가 일치하지 않습니다")]
    ManualHoldMismatch,
}

impl GuardState {
    /// 정상 초기 상태를 만듭니다.
    #[must_use]
    pub fn normal(now: impl Into<String>) -> Self {
        let now = now.into();
        Self {
            schema_version: 1,
            current_mode: GuardMode::Normal,
            manual_hold: false,
            policy_version: 0,
            last_transition_at: now.clone(),
            last_healthy_at: now,
            active_incident_id: None,
            bypass_enabled: false,
            breach_windows: 0,
            stable_windows: 0,
        }
    }

    /// 저장된 상태의 schema와 불변조건을 검증합니다.
    ///
    /// # Errors
    ///
    /// 미래 schema 또는 수동 고정 불일치를 반환합니다.
    pub fn validate(&self) -> Result<(), StateError> {
        if self.schema_version != 1 {
            return Err(StateError::UnsupportedSchema(self.schema_version));
        }
        if self.manual_hold != (self.current_mode == GuardMode::ManualHold) {
            return Err(StateError::ManualHoldMismatch);
        }
        Ok(())
    }

    /// 단일 spike를 비상 전환으로 승격하지 않는 히스테리시스를 적용합니다.
    #[must_use]
    pub fn transition(mut self, input: &TransitionInput) -> Self {
        if self.manual_hold {
            return self;
        }
        let risky = input.assessment.decision.is_protective();
        if risky {
            self.breach_windows = self.breach_windows.saturating_add(1);
            self.stable_windows = 0;
        } else {
            self.stable_windows = self.stable_windows.saturating_add(1);
            self.breach_windows = 0;
            self.last_healthy_at.clone_from(&input.occurred_at);
        }

        let next = match self.current_mode {
            GuardMode::Normal if risky => GuardMode::Watch,
            GuardMode::Watch if self.breach_windows >= 3 => GuardMode::LocalGuard,
            GuardMode::LocalGuard if self.breach_windows >= 5 && input.distributed_pressure => {
                GuardMode::EmergencyProxy
            }
            GuardMode::EmergencyProxy if !risky && input.provider_verified => GuardMode::Recovering,
            GuardMode::LocalGuard if self.stable_windows >= 3 => GuardMode::Recovering,
            GuardMode::Watch if self.stable_windows >= 2 => GuardMode::Normal,
            GuardMode::Recovering if self.stable_windows >= 5 => GuardMode::Normal,
            current => current,
        };
        if next != self.current_mode {
            self.current_mode = next;
            self.last_transition_at.clone_from(&input.occurred_at);
        }
        self
    }

    /// 자동 전이를 수동 고정합니다.
    #[must_use]
    pub fn hold(mut self, now: impl Into<String>) -> Self {
        self.current_mode = GuardMode::ManualHold;
        self.manual_hold = true;
        self.last_transition_at = now.into();
        self
    }

    /// 수동 고정을 해제하고 관찰 상태로 복귀합니다.
    #[must_use]
    pub fn resume(mut self, now: impl Into<String>) -> Self {
        self.current_mode = GuardMode::Watch;
        self.manual_hold = false;
        self.breach_windows = 0;
        self.stable_windows = 0;
        self.last_transition_at = now.into();
        self
    }
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
