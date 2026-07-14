//! Bounded limiter 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use super::{BoundedRateLimiter, LimitDecision, RouteClass};

#[test]
fn enforces_limit_per_client_and_route_class() {
    let limiter = BoundedRateLimiter::new(4);
    let client = ip("192.0.2.10");
    assert_eq!(
        limiter.check(client, RouteClass::Strict, 1, UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(client, RouteClass::Strict, 1, UNIX_EPOCH),
        LimitDecision::Deny
    );
    assert_eq!(
        limiter.check(client, RouteClass::Upload, 1, UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(client, RouteClass::ManagementAuth, 1, UNIX_EPOCH),
        LimitDecision::Allow
    );
}

#[test]
fn never_grows_past_capacity() {
    let limiter = BoundedRateLimiter::new(2);
    assert_eq!(
        limiter.check(ip("192.0.2.1"), RouteClass::General, 10, UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(ip("192.0.2.2"), RouteClass::General, 10, UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(ip("192.0.2.3"), RouteClass::General, 10, UNIX_EPOCH),
        LimitDecision::CapacityReached
    );
    assert_eq!(limiter.tracked_entries(), 2);
}

#[test]
fn removes_old_window_entries() {
    let limiter = BoundedRateLimiter::new(1);
    assert_eq!(
        limiter.check(ip("192.0.2.1"), RouteClass::General, 10, UNIX_EPOCH),
        LimitDecision::Allow
    );
    let next_minute = UNIX_EPOCH + Duration::from_secs(60);
    assert_eq!(
        limiter.check(ip("192.0.2.2"), RouteClass::General, 10, next_minute),
        LimitDecision::Allow
    );
    assert_eq!(limiter.tracked_entries(), 1);
}

fn ip(raw: &str) -> IpAddr {
    raw.parse::<IpAddr>().expect("valid IP fixture")
}
