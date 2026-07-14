use super::FixedWindowRateLimiter;
use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn test_fixed_window_rate_limiter() {
    let limiter = FixedWindowRateLimiter::default();
    let client_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let first_minute = UNIX_EPOCH + Duration::from_secs(60);
    let second_minute = UNIX_EPOCH + Duration::from_secs(120);

    assert!(limiter.allow(client_ip, 2, first_minute));
    assert!(limiter.allow(client_ip, 2, first_minute));
    assert!(!limiter.allow(client_ip, 2, first_minute));
    assert!(limiter.allow(client_ip, 2, second_minute));
}

#[test]
fn test_fixed_window_rate_limiter_evicts_stale_entries() {
    let limiter = FixedWindowRateLimiter::default();
    let first_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let second_ip = "127.0.0.2".parse::<IpAddr>().unwrap();
    let first_minute = UNIX_EPOCH + Duration::from_secs(60);
    let second_minute = UNIX_EPOCH + Duration::from_secs(120);

    assert!(limiter.allow(first_ip, 10, first_minute));
    assert_eq!(limiter.tracked_clients_len(), 1);

    assert!(limiter.allow(second_ip, 10, second_minute));
    assert_eq!(limiter.tracked_clients_len(), 1);
}

#[test]
fn test_fixed_window_rate_limiter_recovers_from_poisoned_mutex() {
    let limiter = FixedWindowRateLimiter::default();
    let _ = std::panic::catch_unwind(|| {
        let _guard = limiter.state.lock().unwrap();
        panic!("poison mutex");
    });

    let client_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(60);

    assert!(limiter.allow(client_ip, 1, now));
    assert_eq!(limiter.tracked_clients_len(), 1);
}
