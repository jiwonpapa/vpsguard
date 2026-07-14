use super::EdgeProxyApp;
use crate::runtime_config::EdgeRuntimeConfig;
use common::network::parse_allowed_ip_rules;

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
        thumb_path_prefixes: Vec::new(),
        strict_rate_limit_path_prefixes: vec!["/login".to_string()],
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
        upload_rate_limit_requests_per_minute: None,
        thumb_rate_limit_requests_per_minute: None,
        strict_rate_limit_requests_per_minute: None,
    }
}

#[test]
fn test_host_allowed_accepts_canonical_host() {
    let mut config = sample_runtime_config();
    config.allowed_hosts = vec!["legacy.wolchuck.cc".to_string()];
    config.passthrough_hosts = vec!["w3.wolchuck.co.kr".to_string()];
    config.canonical_host = Some("www.wolchuck.cc".to_string());
    config.trusted_proxy_rules = parse_allowed_ip_rules(&["127.0.0.1".to_string()]);
    config.gone_paths = vec!["/deprecated-endpoint".to_string()];
    let app = EdgeProxyApp::new(config);

    assert!(app.host_allowed(Some("www.wolchuck.cc")));
    assert!(app.host_allowed(Some("legacy.wolchuck.cc")));
    assert!(app.host_allowed(Some("w3.wolchuck.co.kr")));
    assert!(!app.host_allowed(Some("bad.wolchuck.cc")));
}

#[test]
fn test_host_allowed_supports_wildcard_suffix_rules() {
    let mut config = sample_runtime_config();
    config.allowed_hosts = vec!["*.wolchuck.co.kr".to_string()];
    config.passthrough_hosts = vec!["wolchuck.co.kr".to_string()];
    config.canonical_host = Some("wolchuck.cc".to_string());
    let app = EdgeProxyApp::new(config);

    assert!(app.host_allowed(Some("w3.wolchuck.co.kr")));
    assert!(app.host_allowed(Some("admin.wolchuck.co.kr")));
    assert!(app.host_allowed(Some("wolchuck.co.kr")));
    assert!(!app.host_allowed(Some("evilwolchuck.co.kr")));
}

#[test]
fn test_passthrough_host_skips_canonical_redirect() {
    let mut config = sample_runtime_config();
    config.allowed_hosts = vec!["wolchuck.cc".to_string()];
    config.passthrough_hosts = vec!["w3.wolchuck.co.kr".to_string()];
    config.canonical_host = Some("wolchuck.cc".to_string());
    let app = EdgeProxyApp::new(config);

    assert!(app.host_passthrough(Some("w3.wolchuck.co.kr")));
    assert!(!app.host_passthrough(Some("wolchuck.cc")));
}

#[test]
fn test_passthrough_host_supports_wildcard_suffix_rules() {
    let mut config = sample_runtime_config();
    config.allowed_hosts = vec!["wolchuck.cc".to_string()];
    config.passthrough_hosts =
        vec!["wolchuck.co.kr".to_string(), "*.wolchuck.co.kr".to_string()];
    config.canonical_host = Some("wolchuck.cc".to_string());
    let app = EdgeProxyApp::new(config);

    assert!(app.host_passthrough(Some("w3.wolchuck.co.kr")));
    assert!(app.host_passthrough(Some("wolchuck.co.kr")));
    assert!(!app.host_passthrough(Some("wolchuck.cc")));
}

#[test]
fn test_admin_ip_allowed_supports_cidr() {
    let mut config = sample_runtime_config();
    config.admin_allowed_rules = parse_allowed_ip_rules(&[
        "127.0.0.1".to_string(),
        "10.0.0.0/8".to_string(),
    ]);
    config.trusted_proxy_rules = parse_allowed_ip_rules(&["127.0.0.1".to_string()]);
    config.gone_paths = vec!["/deprecated-endpoint".to_string()];
    let app = EdgeProxyApp::new(config);

    assert!(app.admin_ip_allowed(Some("127.0.0.1".parse().unwrap())));
    assert!(app.admin_ip_allowed(Some("10.1.2.3".parse().unwrap())));
    assert!(!app.admin_ip_allowed(Some("192.168.0.1".parse().unwrap())));
}

#[test]
fn test_admin_and_gone_path_rules_from_config() {
    let mut config = sample_runtime_config();
    config.trusted_proxy_rules = parse_allowed_ip_rules(&["127.0.0.1".to_string()]);
    config.thumb_path_prefixes = vec!["/thumb".to_string(), "/thumbserver".to_string()];
    config.strict_rate_limit_path_prefixes = vec!["/login".to_string(), "/search".to_string()];
    config.gone_paths = vec!["/deprecated-endpoint".to_string()];
    let app = EdgeProxyApp::new(config);

    assert!(app.is_admin_path("/metrics"));
    assert!(!app.is_admin_path("/ops/reload"));
    assert!(app.is_upload_path("/upload"));
    assert!(app.is_upload_path("/upload/image"));
    assert!(app.is_thumb_path("/thumb/w_50/example.jpg"));
    assert!(app.is_thumb_path("/thumbserver/100x100/example.webp"));
    assert!(app.is_strict_rate_limit_path("/login"));
    assert!(app.is_strict_rate_limit_path("/search/query"));
    assert!(app.is_gone_path("/deprecated-endpoint"));
    assert!(!app.is_gone_path("/upload"));
}

#[test]
fn test_blocked_ip_denied_supports_ip_and_cidr() {
    let mut config = sample_runtime_config();
    config.blocked_rules = parse_allowed_ip_rules(&[
        "203.0.113.10".to_string(),
        "198.51.100.0/24".to_string(),
    ]);
    let app = EdgeProxyApp::new(config);

    assert!(app.blocked_ip_denied(Some("203.0.113.10".parse().unwrap())));
    assert!(app.blocked_ip_denied(Some("198.51.100.42".parse().unwrap())));
    assert!(!app.blocked_ip_denied(Some("192.0.2.42".parse().unwrap())));
}
