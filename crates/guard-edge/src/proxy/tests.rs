//! HTTP redirect와 ACME 예외 회귀 테스트입니다.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    https_redirect_location, masked_client_network, sampled_occurrence, select_request_host,
    stricter_limit,
};

#[test]
fn uses_http2_authority_when_host_header_is_absent() {
    assert_eq!(
        select_request_host(None, Some("guard.example.test:443")),
        Some("guard.example.test:443".to_owned())
    );
    assert_eq!(
        select_request_host(Some("example.test".to_owned()), Some("ignored.test")),
        Some("example.test".to_owned())
    );
}

#[test]
fn redirects_plain_http_to_canonical_https() {
    assert_eq!(
        https_redirect_location(
            true,
            false,
            Some("www.example.com"),
            "example.com:80",
            "/board?page=1",
        ),
        Some("https://www.example.com/board?page=1".to_owned())
    );
}

#[test]
fn keeps_https_and_http01_challenge_on_the_current_listener() {
    assert_eq!(
        https_redirect_location(true, true, None, "example.com", "/"),
        None
    );
    assert_eq!(
        https_redirect_location(
            true,
            false,
            None,
            "example.com",
            "/.well-known/acme-challenge/token",
        ),
        None
    );
}

#[test]
fn authentication_limit_never_weakens_an_incident_limit() {
    assert_eq!(stricter_limit(Some(30), Some(10)), Some(10));
    assert_eq!(stricter_limit(Some(5), Some(10)), Some(5));
    assert_eq!(stricter_limit(None, Some(10)), Some(10));
    assert_eq!(stricter_limit(None, None), None);
}

#[test]
fn repeated_rejections_are_sampled_and_client_networks_are_masked() {
    assert!(sampled_occurrence(1));
    assert!(!sampled_occurrence(2));
    assert!(sampled_occurrence(100));
    assert_eq!(
        masked_client_network(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 49)))),
        Some("203.0.113.0/24".to_owned())
    );
    assert_eq!(
        masked_client_network(Some(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 1, 2, 3, 4, 5, 6,
        )))),
        Some("2001:db8:1:2::/64".to_owned())
    );
}
