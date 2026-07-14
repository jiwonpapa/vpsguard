use super::{
    canonical_redirect_location, effective_client_ip_from_headers, effective_proto,
    path_matches_rule, select_rate_limit,
};
use crate::runtime_config::EdgeRuntimeConfig;
use std::net::IpAddr;

fn sample_runtime_config() -> EdgeRuntimeConfig {
    EdgeRuntimeConfig {
        listen_addr: "127.0.0.1:9081".to_string(),
        tls_listen_addr: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        upstream_tls: false,
        upstream_sni: "irongate".to_string(),
        allowed_hosts: Vec::new(),
        passthrough_hosts: Vec::new(),
        canonical_host: None,
        admin_allowed_rules: Vec::new(),
        blocked_rules: Vec::new(),
        trusted_proxy_rules: Vec::new(),
        admin_path_prefixes: vec!["/metrics".to_string()],
        upload_path_prefixes: vec!["/upload".to_string()],
        thumb_path_prefixes: vec!["/thumb".to_string(), "/thumbserver".to_string()],
        strict_rate_limit_path_prefixes: vec!["/login".to_string(), "/search".to_string()],
        gone_paths: Vec::new(),
        request_id_header: "x-request-id".to_string(),
        max_body_bytes: None,
        upload_max_body_bytes: None,
        downstream_read_timeout: None,
        upload_downstream_read_timeout: None,
        downstream_write_timeout: None,
        downstream_total_drain_timeout: None,
        upstream_connect_timeout: None,
        upstream_read_timeout: None,
        upload_upstream_read_timeout: None,
        upstream_write_timeout: None,
        upstream_idle_timeout: None,
        rate_limit_requests_per_minute: None,
        upload_rate_limit_requests_per_minute: Some(30),
        thumb_rate_limit_requests_per_minute: Some(45),
        strict_rate_limit_requests_per_minute: Some(60),
    }
}

#[test]
fn test_canonical_redirect_location() {
    let location = canonical_redirect_location("https", "www.wolchuck.cc", "/board?id=1");
    assert_eq!(location, "https://www.wolchuck.cc/board?id=1");
}

#[test]
fn test_effective_client_ip_ignores_untrusted_forwarded_for() {
    let direct_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let effective =
        effective_client_ip_from_headers(Some("203.0.113.55"), Some(direct_ip), false);

    assert_eq!(effective, Some(direct_ip));
}

#[test]
fn test_effective_client_ip_uses_trusted_forwarded_for() {
    let direct_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let forwarded_ip: IpAddr = "203.0.113.55".parse().unwrap();
    let effective =
        effective_client_ip_from_headers(Some("203.0.113.55, 127.0.0.1"), Some(direct_ip), true);

    assert_eq!(effective, Some(forwarded_ip));
}

#[test]
fn test_effective_proto_ignores_untrusted_forwarded_proto() {
    assert_eq!(
        effective_proto(Some("https"), false, false),
        "http".to_string()
    );
    assert_eq!(
        effective_proto(Some("http"), true, false),
        "https".to_string()
    );
}

#[test]
fn test_path_matches_rule() {
    assert!(path_matches_rule(
        "/deprecated-endpoint",
        "/deprecated-endpoint"
    ));
    assert!(path_matches_rule("/ops/health", "/ops"));
    assert!(!path_matches_rule("/upload", "/deprecated-endpoint"));
}

#[test]
fn test_select_rate_limit_skips_general_public_paths_when_global_limit_is_unset() {
    let config = sample_runtime_config();

    assert_eq!(select_rate_limit("/boards/freebd", &config), None);
    assert_eq!(
        select_rate_limit("/bbs/board.php?bo_table=freebd", &config),
        None
    );
    assert_eq!(select_rate_limit("/login", &config), Some(60));
    assert_eq!(select_rate_limit("/search", &config), Some(60));
    assert_eq!(select_rate_limit("/upload/image", &config), Some(30));
    assert_eq!(select_rate_limit("/thumb/w_50/image.jpg", &config), Some(45));
    assert_eq!(
        select_rate_limit("/thumbserver/100x100/a.webp", &config),
        Some(45)
    );
}

#[test]
fn test_select_rate_limit_prefers_strict_over_thumb_when_path_matches_both() {
    let mut config = sample_runtime_config();
    config.thumb_path_prefixes = vec!["/thumb".to_string()];
    config.strict_rate_limit_path_prefixes = vec!["/thumb".to_string()];

    assert_eq!(select_rate_limit("/thumb/w_50/image.jpg", &config), Some(60));
}
