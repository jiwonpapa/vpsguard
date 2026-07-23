//! 상태 전이 회귀 테스트입니다.

use crate::detection::{Assessment, Decision, ReasonCode};

use super::{GuardMode, GuardState, TransitionInput};

fn input(decision: Decision, at: &str) -> TransitionInput {
    TransitionInput {
        assessment: Assessment {
            trust_score: 10,
            bot_likelihood: 90,
            resource_cost: 90,
            confidence: 100,
            decision,
            reason_codes: vec![ReasonCode::AutomationPattern],
        },
        distributed_pressure: true,
        provider_verified: true,
        occurred_at: at.to_owned(),
    }
}

#[test]
fn single_spike_never_enters_emergency() {
    let state = GuardState::normal("2026-07-14T00:00:00Z")
        .transition(&input(Decision::Deny, "2026-07-14T00:00:01Z"));
    assert_eq!(state.current_mode, GuardMode::Watch);
}

#[test]
fn sustained_pressure_reaches_local_then_emergency() {
    let mut state = GuardState::normal("2026-07-14T00:00:00Z");
    for second in 1..=5 {
        state = state.transition(&input(
            Decision::Deny,
            &format!("2026-07-14T00:00:0{second}Z"),
        ));
    }
    assert_eq!(state.current_mode, GuardMode::EmergencyProxy);
}

#[test]
fn manual_hold_blocks_automatic_transition() {
    let state = GuardState::normal("2026-07-14T00:00:00Z")
        .hold("2026-07-14T00:00:01Z")
        .transition(&input(Decision::Deny, "2026-07-14T00:00:02Z"));
    assert_eq!(state.current_mode, GuardMode::ManualHold);
}

#[test]
fn emergency_requires_five_stable_windows_before_recovery_approval() {
    let mut state = GuardState::normal("2026-07-14T00:00:00Z");
    state.current_mode = GuardMode::EmergencyProxy;
    for second in 1..5 {
        state = state.transition(&input(
            Decision::Allow,
            &format!("2026-07-14T00:01:0{second}Z"),
        ));
        assert_eq!(state.current_mode, GuardMode::EmergencyProxy);
    }
    state = state.transition(&input(Decision::Allow, "2026-07-14T00:01:05Z"));
    assert_eq!(state.current_mode, GuardMode::RecoveryReady);
}

#[test]
fn recovery_ready_never_auto_restores_and_risk_reactivates_emergency() {
    let mut state = GuardState::normal("2026-07-14T00:00:00Z");
    state.current_mode = GuardMode::RecoveryReady;
    for second in 1..=10 {
        state = state.transition(&input(
            Decision::Allow,
            &format!("2026-07-14T00:02:{second:02}Z"),
        ));
    }
    assert_eq!(state.current_mode, GuardMode::RecoveryReady);

    state = state.transition(&input(Decision::Throttle, "2026-07-14T00:03:00Z"));
    assert_eq!(state.current_mode, GuardMode::EmergencyProxy);
}
