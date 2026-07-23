//! 설명 가능한 규칙 기반 탐지 점수와 판정을 제공합니다.

use serde::{Deserialize, Serialize};

/// OS collector에서 계산한 bounded host 자원 압력입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostPressure {
    score: u8,
    signals_available: bool,
}

impl HostPressure {
    /// 최신 host 신호가 있을 때 0..=100으로 고정한 압력을 만듭니다.
    #[must_use]
    pub const fn available(score: u8) -> Self {
        Self {
            score: if score > 100 { 100 } else { score },
            signals_available: true,
        }
    }

    /// host collector 신호가 없거나 최신이 아닐 때의 값을 만듭니다.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            score: 0,
            signals_available: false,
        }
    }

    /// 0..=100 host 압력을 반환합니다.
    #[must_use]
    pub const fn score(self) -> u8 {
        self.score
    }

    /// 최신 host collector 신호가 있는지 반환합니다.
    #[must_use]
    pub const fn signals_available(self) -> bool {
        self.signals_available
    }
}

/// 탐지 입력의 결손 여부를 포함한 bounded 신호입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionInput {
    /// 검증된 identity 또는 정상 session 신뢰도입니다.
    pub trust: u8,
    /// 자동화 행동 점수입니다.
    pub automation: u8,
    /// route 기본 비용입니다.
    pub route_cost: u8,
    /// upstream 지연 가중치입니다.
    pub upstream_pressure: u8,
    /// CPU·load·memory·swap으로 합성한 host 자원 압력입니다.
    pub host_pressure: HostPressure,
    /// 정상 session cookie가 이어지는지 여부입니다.
    pub session_continuity: bool,
    /// 검색봇 identity가 UA 외 신호로 검증됐는지 여부입니다.
    pub crawler_verified: bool,
}

/// 사람이 읽을 수 있는 판정 근거 코드입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// 자동화 행동이 강합니다.
    AutomationPattern,
    /// 고비용 경로를 사용합니다.
    ExpensiveRoute,
    /// upstream 자원 압력이 높습니다.
    UpstreamPressure,
    /// host CPU·load·memory·swap 압력이 높습니다.
    HostResourcePressure,
    /// 정상 session 연속성이 없습니다.
    NoSessionContinuity,
    /// 검색봇 identity가 검증됐습니다.
    VerifiedCrawler,
    /// 자원 collector 신호가 누락됐습니다.
    ResourceSignalsMissing,
    /// 정상 session 신뢰 신호가 있습니다.
    TrustedIdentity,
}

/// 탐지 결과가 권고하는 요청 처리입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// 요청을 허용합니다.
    Allow,
    /// 상세 관찰합니다.
    Observe,
    /// 속도를 제한합니다.
    Throttle,
    /// 브라우저 검증을 요구합니다.
    Challenge,
    /// TTL 기반 임시 거부를 권고합니다.
    Deny,
}

impl Decision {
    /// 로컬 보호가 필요한 판정인지 반환합니다.
    #[must_use]
    pub const fn is_protective(self) -> bool {
        matches!(self, Self::Throttle | Self::Challenge | Self::Deny)
    }
}

/// 세 점수와 근거를 포함하는 설명 가능한 판정입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    /// 신뢰 점수 0..=100입니다.
    pub trust_score: u8,
    /// 봇 가능성 0..=100입니다.
    pub bot_likelihood: u8,
    /// 자원 비용 0..=100입니다.
    pub resource_cost: u8,
    /// 입력 완성도 0..=100입니다.
    pub confidence: u8,
    /// 권고 판정입니다.
    pub decision: Decision,
    /// 판정 근거입니다.
    pub reason_codes: Vec<ReasonCode>,
}

/// 결정론적 MVP 탐지기입니다.
#[derive(Debug, Default, Clone, Copy)]
pub struct Detector;

impl Detector {
    /// 입력을 0..=100으로 고정하고 모든 판정에 근거를 생성합니다.
    #[must_use]
    pub fn assess(input: &DetectionInput) -> Assessment {
        let trust_score = input.trust.min(100);
        let mut bot = input.automation.min(100);
        let host_pressure = if input.host_pressure.signals_available() {
            input.host_pressure.score()
        } else {
            0
        };
        let effective_pressure = input.upstream_pressure.min(100).max(host_pressure);
        let cost = input
            .route_cost
            .min(100)
            .saturating_add(effective_pressure / 2)
            .min(100);
        let mut reasons = Vec::with_capacity(7);

        if input.automation >= 50 {
            reasons.push(ReasonCode::AutomationPattern);
        }
        if input.route_cost >= 50 {
            reasons.push(ReasonCode::ExpensiveRoute);
        }
        if input.upstream_pressure >= 50 {
            reasons.push(ReasonCode::UpstreamPressure);
        }
        if host_pressure >= 50 {
            reasons.push(ReasonCode::HostResourcePressure);
        }
        if input.session_continuity {
            bot = bot.saturating_sub(20);
            reasons.push(ReasonCode::TrustedIdentity);
        } else {
            reasons.push(ReasonCode::NoSessionContinuity);
        }
        if input.crawler_verified {
            bot = bot.saturating_sub(35);
            reasons.push(ReasonCode::VerifiedCrawler);
        }
        let confidence = if input.host_pressure.signals_available() {
            100
        } else {
            reasons.push(ReasonCode::ResourceSignalsMissing);
            60
        };

        let decision = if cost >= 80 && bot >= 80 && trust_score < 40 {
            Decision::Deny
        } else if cost >= 65 && bot >= 60 && trust_score < 60 {
            Decision::Challenge
        } else if cost >= 60 {
            Decision::Throttle
        } else if bot >= 60 && trust_score < 50 {
            Decision::Observe
        } else {
            Decision::Allow
        };
        Assessment {
            trust_score,
            bot_likelihood: bot,
            resource_cost: cost,
            confidence,
            decision,
            reason_codes: reasons,
        }
    }
}

#[cfg(test)]
#[path = "detection/tests.rs"]
mod tests;
