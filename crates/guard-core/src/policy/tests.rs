//! 정책 hash와 만료 회귀 테스트입니다.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    PolicyError, PolicySnapshot, ProtectionSettings, ProtectionSettingsError, StaticLimits,
};
use crate::state::GuardMode;

fn sample() -> PolicySnapshot {
    PolicySnapshot {
        schema_version: 1,
        policy_version: 7,
        generated_at: "2026-07-14T00:00:00Z".to_owned(),
        expires_at: "2026-07-14T00:10:00Z".to_owned(),
        mode: GuardMode::Watch,
        route_rules: Vec::new(),
        client_rules: Vec::new(),
        static_limits: StaticLimits {
            max_body_bytes: 1_048_576,
            max_tracked_clients: 10_000,
        },
        content_sha256: String::new(),
    }
}

#[test]
fn default_protection_settings_preserve_the_existing_mode_limits() {
    let settings = ProtectionSettings::default();
    assert_eq!(
        settings
            .route_rules(GuardMode::Watch)
            .iter()
            .map(|rule| (rule.route_class.as_str(), rule.requests_per_minute))
            .collect::<Vec<_>>(),
        vec![("strict", 120)]
    );
    assert_eq!(
        settings
            .route_rules(GuardMode::LocalGuard)
            .iter()
            .map(|rule| (rule.route_class.as_str(), rule.requests_per_minute))
            .collect::<Vec<_>>(),
        vec![("strict", 30), ("upload", 15)]
    );
    assert_eq!(
        settings
            .route_rules(GuardMode::EmergencyProxy)
            .iter()
            .map(|rule| (rule.route_class.as_str(), rule.requests_per_minute))
            .collect::<Vec<_>>(),
        vec![("strict", 10), ("upload", 5)]
    );
}

#[test]
fn protection_settings_reject_unsafe_ranges_and_non_progressive_stages() {
    let settings = ProtectionSettings {
        watch_strict_requests_per_minute: 0,
        ..ProtectionSettings::default()
    };
    assert_eq!(
        settings.validate(),
        Err(ProtectionSettingsError::OutOfRange(
            "watch_strict_requests_per_minute"
        ))
    );

    let defaults = ProtectionSettings::default();
    let settings = ProtectionSettings {
        emergency_strict_requests_per_minute: defaults.local_strict_requests_per_minute + 1,
        ..defaults
    };
    assert_eq!(
        settings.validate(),
        Err(ProtectionSettingsError::StageOrder(
            "emergency_strict_requests_per_minute"
        ))
    );

    let defaults = ProtectionSettings::default();
    let settings = ProtectionSettings {
        local_upload_requests_per_minute: defaults.local_strict_requests_per_minute + 1,
        ..defaults
    };
    assert_eq!(
        settings.validate(),
        Err(ProtectionSettingsError::StageOrder(
            "local_upload_requests_per_minute"
        ))
    );

    let settings = ProtectionSettings {
        emergency_strict_requests_per_minute: 4,
        ..ProtectionSettings::default()
    };
    assert_eq!(
        settings.validate(),
        Err(ProtectionSettingsError::StageOrder(
            "emergency_upload_requests_per_minute"
        ))
    );
}

fn at(raw: &str) -> OffsetDateTime {
    OffsetDateTime::parse(raw, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[test]
fn sealed_policy_validates() -> Result<(), PolicyError> {
    let policy = sample().seal()?;
    assert_eq!(policy.validate_at(at("2026-07-14T00:05:00Z")), Ok(()));
    Ok(())
}

#[test]
fn mutation_after_seal_is_rejected() -> Result<(), PolicyError> {
    let mut policy = sample().seal()?;
    policy.policy_version = 8;
    assert_eq!(
        policy.validate_at(at("2026-07-14T00:05:00Z")),
        Err(PolicyError::HashMismatch)
    );
    Ok(())
}

#[test]
fn expired_policy_is_rejected() -> Result<(), PolicyError> {
    let policy = sample().seal()?;
    assert_eq!(
        policy.validate_at(at("2026-07-14T00:11:00Z")),
        Err(PolicyError::Expired)
    );
    Ok(())
}
