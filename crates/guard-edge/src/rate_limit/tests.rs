//! Bounded limiter 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use super::{BoundedRateLimiter, LimitDecision, LimitScope, RateLimitPolicy, RouteClass};

#[test]
fn enforces_limit_per_client_and_route_class() {
    let limiter = BoundedRateLimiter::new(4);
    let client = ip("192.0.2.10");
    assert_eq!(
        limiter.check(client, RouteClass::Strict, policy(1), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(client, RouteClass::Strict, policy(1), UNIX_EPOCH),
        LimitDecision::Deny(LimitScope::Client)
    );
    assert_eq!(
        limiter.check(client, RouteClass::Upload, policy(1), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(client, RouteClass::Authentication, policy(1), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(client, RouteClass::ManagementAuth, policy(1), UNIX_EPOCH),
        LimitDecision::Allow
    );
}

#[test]
fn never_grows_past_capacity() {
    let limiter = BoundedRateLimiter::new(2);
    assert_eq!(
        limiter.check(ip("192.0.2.1"), RouteClass::General, policy(10), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(ip("192.0.2.2"), RouteClass::General, policy(10), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(ip("192.0.2.3"), RouteClass::General, policy(10), UNIX_EPOCH),
        LimitDecision::AllowFallback
    );
    assert_eq!(limiter.tracked_entries(), 2);
}

#[test]
fn removes_old_window_entries() {
    let limiter = BoundedRateLimiter::new(1);
    assert_eq!(
        limiter.check(ip("192.0.2.1"), RouteClass::General, policy(10), UNIX_EPOCH),
        LimitDecision::Allow
    );
    let next_minute = UNIX_EPOCH + Duration::from_secs(60);
    assert_eq!(
        limiter.check(
            ip("192.0.2.2"),
            RouteClass::General,
            policy(10),
            next_minute
        ),
        LimitDecision::Allow
    );
    assert_eq!(limiter.tracked_entries(), 1);
}

#[test]
fn rotating_clients_cannot_bypass_route_and_global_fallback() {
    let limiter = BoundedRateLimiter::new(1);
    let bounded = RateLimitPolicy {
        client_rpm: 10,
        prefix_rpm: 10,
        route_rpm: 3,
        global_rpm: 4,
    };
    assert_eq!(
        limiter.check(ip("192.0.2.1"), RouteClass::General, bounded, UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(ip("198.51.100.1"), RouteClass::General, bounded, UNIX_EPOCH),
        LimitDecision::AllowFallback
    );
    assert_eq!(
        limiter.check(ip("203.0.113.1"), RouteClass::General, bounded, UNIX_EPOCH),
        LimitDecision::AllowFallback
    );
    assert_eq!(
        limiter.check(ip("2001:db8::1"), RouteClass::General, bounded, UNIX_EPOCH),
        LimitDecision::Deny(LimitScope::Route)
    );
    assert_eq!(limiter.tracked_entries(), 1);
}

#[test]
fn shared_ip_limit_expires_at_the_next_minute() {
    let limiter = BoundedRateLimiter::new(4);
    let shared_ip = ip("192.0.2.10");
    assert_eq!(
        limiter.check(shared_ip, RouteClass::Strict, policy(1), UNIX_EPOCH),
        LimitDecision::Allow
    );
    assert_eq!(
        limiter.check(shared_ip, RouteClass::Strict, policy(1), UNIX_EPOCH),
        LimitDecision::Deny(LimitScope::Client)
    );
    assert_eq!(
        limiter.check(
            shared_ip,
            RouteClass::Strict,
            policy(1),
            UNIX_EPOCH + Duration::from_secs(60),
        ),
        LimitDecision::Allow
    );
}

const fn policy(client_rpm: u32) -> RateLimitPolicy {
    RateLimitPolicy::from_multipliers(client_rpm, 32, 128, 256)
}

fn ip(raw: &str) -> IpAddr {
    raw.parse::<IpAddr>().expect("valid IP fixture")
}
