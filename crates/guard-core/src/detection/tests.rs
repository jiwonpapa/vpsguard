//! 탐지 회귀 테스트입니다.

use super::{Decision, DetectionInput, Detector, ReasonCode};

#[test]
fn normal_session_is_allowed() {
    let result = Detector::assess(&DetectionInput {
        trust: 90,
        automation: 20,
        route_cost: 20,
        upstream_pressure: 10,
        resource_signals_available: true,
        session_continuity: true,
        crawler_verified: false,
    });
    assert_eq!(result.decision, Decision::Allow);
    assert!(result.reason_codes.contains(&ReasonCode::TrustedIdentity));
}

#[test]
fn expensive_verified_crawler_is_throttled_not_denied() {
    let result = Detector::assess(&DetectionInput {
        trust: 75,
        automation: 95,
        route_cost: 80,
        upstream_pressure: 80,
        resource_signals_available: true,
        session_continuity: false,
        crawler_verified: true,
    });
    assert_eq!(result.decision, Decision::Throttle);
}

#[test]
fn missing_collectors_reduce_confidence() {
    let result = Detector::assess(&DetectionInput {
        trust: 10,
        automation: 90,
        route_cost: 40,
        upstream_pressure: 100,
        resource_signals_available: false,
        session_continuity: false,
        crawler_verified: false,
    });
    assert_eq!(result.confidence, 60);
    assert_eq!(result.resource_cost, 40);
    assert!(
        result
            .reason_codes
            .contains(&ReasonCode::ResourceSignalsMissing)
    );
}
