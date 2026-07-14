//! Control 정책 lease 갱신 회귀 테스트입니다.

use std::time::{Duration, Instant};

use guard_core::GuardMode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{POLICY_REFRESH_INTERVAL, build_policy, policy_renewal_due};

#[test]
fn policy_refresh_is_due_before_the_ten_minute_lease_expires() {
    let now = Instant::now();
    assert!(policy_renewal_due(None, now));
    assert!(!policy_renewal_due(
        Some(now - Duration::from_secs(4 * 60)),
        now
    ));
    assert!(policy_renewal_due(Some(now - POLICY_REFRESH_INTERVAL), now));
}

#[test]
fn generated_policy_keeps_a_ten_minute_bounded_lease() -> Result<(), Box<dyn std::error::Error>> {
    let policy = build_policy(GuardMode::LocalGuard, 8, 1_024, 100)?;
    let generated = OffsetDateTime::parse(&policy.generated_at, &Rfc3339)?;
    let expires = OffsetDateTime::parse(&policy.expires_at, &Rfc3339)?;
    assert_eq!(expires - generated, time::Duration::minutes(10));
    Ok(())
}
