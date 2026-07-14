//! Edge 순수 정책 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;

use ipnet::IpNet;

use super::{
    effective_client_ip, host_allowed, host_matches_rule, normalize_host, path_matches_rule,
};

#[test]
fn normalizes_host_case_port_and_trailing_dot() {
    assert_eq!(normalize_host("WWW.Example.COM:443"), "www.example.com");
    assert_eq!(normalize_host("www.example.com."), "www.example.com");
}

#[test]
fn wildcard_requires_a_real_subdomain() {
    assert!(host_matches_rule("api.example.com", "*.example.com"));
    assert!(!host_matches_rule("a.b.example.com", "*.example.com"));
    assert!(!host_matches_rule("example.com", "*.example.com"));
    assert!(!host_matches_rule("evil-example.com", "*.example.com"));
}

#[test]
fn rejects_missing_or_unlisted_host() {
    let rules = vec!["example.com".to_owned(), "*.example.com".to_owned()];
    assert!(host_allowed(Some("api.example.com"), &rules));
    assert!(!host_allowed(Some("attacker.invalid"), &rules));
    assert!(!host_allowed(None, &rules));
}

#[test]
fn path_rule_is_segment_aware() {
    assert!(path_matches_rule("/search", "/search"));
    assert!(path_matches_rule("/search/results", "/search"));
    assert!(!path_matches_rule("/searching", "/search"));
}

#[test]
fn ignores_forwarded_header_from_untrusted_peer() {
    let direct = ip("198.51.100.7");
    let trusted = vec![network("127.0.0.1/32")];
    assert_eq!(
        effective_client_ip(direct, Some("203.0.113.9"), &trusted),
        direct
    );
}

#[test]
fn removes_trusted_proxies_from_right_of_chain() {
    let direct = ip("127.0.0.1");
    let trusted = vec![network("127.0.0.0/8"), network("10.0.0.0/8")];
    assert_eq!(
        effective_client_ip(direct, Some("203.0.113.9, 10.1.2.3, 127.0.0.2"), &trusted,),
        ip("203.0.113.9")
    );
}

#[test]
fn malformed_forwarded_chain_falls_back_to_direct_peer() {
    let direct = ip("127.0.0.1");
    let trusted = vec![network("127.0.0.0/8")];
    assert_eq!(
        effective_client_ip(direct, Some("203.0.113.9, invalid"), &trusted),
        direct
    );
}

fn ip(raw: &str) -> IpAddr {
    raw.parse::<IpAddr>().expect("valid IP fixture")
}

fn network(raw: &str) -> IpNet {
    raw.parse::<IpNet>().expect("valid CIDR fixture")
}
