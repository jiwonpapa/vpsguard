//! Edge runtime 설정 불변조건 회귀 테스트입니다.

use guard_core::GuardConfig;

use super::EdgeRuntimeConfig;
use crate::rate_limit::RouteClass;

#[test]
fn observe_mode_never_enables_dynamic_rate_limits() -> Result<(), Box<dyn std::error::Error>> {
    let config = GuardConfig::from_toml(include_str!("../../../../configs/vps-guard.smoke.toml"))?;
    let runtime = EdgeRuntimeConfig::try_from_guard(&config)?;

    assert!(!runtime.enforces_dynamic_protection());
    assert_eq!(runtime.rate_limit(RouteClass::General), None);
    assert_eq!(runtime.rate_limit(RouteClass::Strict), None);
    assert_eq!(runtime.rate_limit(RouteClass::Upload), None);
    Ok(())
}
