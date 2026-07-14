use std::time::Duration;

use common::config::{EdgeProxyConfig as EdgeProxyServiceConfig, EdgeProxyTlsListenerConfig};

use super::EdgeRuntimeConfig;
use crate::runtime_config::normalize_host;

fn sample_service_config() -> EdgeProxyServiceConfig {
    EdgeProxyServiceConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        upstream_tls: false,
        upstream_sni: "irongate".to_string(),
        allowed_hosts: vec!["allowed.local".to_string(), "legacy.local:443".to_string()],
        passthrough_hosts: vec!["passthrough.local".to_string()],
        canonical_host: "allowed.local".to_string(),
        admin_allowed_ips: vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()],
        blocked_ips: vec!["203.0.113.10".to_string()],
        blocked_cidrs: vec!["198.51.100.0/24".to_string()],
        trusted_proxy_cidrs: vec!["127.0.0.1".to_string()],
        admin_path_prefixes: vec!["/metrics".to_string(), "/ops".to_string()],
        upload_path_prefixes: vec!["/upload".to_string()],
        thumb_path_prefixes: vec!["/thumb".to_string(), "/thumbserver".to_string()],
        strict_rate_limit_path_prefixes: vec!["/login".to_string(), "/search".to_string()],
        gone_paths: vec!["/deprecated-endpoint".to_string()],
        request_id_header: "x-request-id".to_string(),
        max_body_bytes: Some(1024),
        upload_max_body_bytes: Some(10 * 1024 * 1024),
        downstream_read_timeout_ms: Some(5_000),
        upload_downstream_read_timeout_ms: Some(60_000),
        downstream_write_timeout_ms: Some(30_000),
        downstream_total_drain_timeout_ms: Some(5_000),
        upstream_connect_timeout_ms: Some(3_000),
        upstream_read_timeout_ms: Some(30_000),
        upload_upstream_read_timeout_ms: Some(60_000),
        upstream_write_timeout_ms: Some(30_000),
        upstream_idle_timeout_ms: Some(30_000),
        rate_limit_requests_per_minute: Some(60),
        upload_rate_limit_requests_per_minute: Some(20),
        thumb_rate_limit_requests_per_minute: Some(45),
        strict_rate_limit_requests_per_minute: Some(30),
        tls_listener: EdgeProxyTlsListenerConfig {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 9444,
            cert_file: "/tmp/cert.pem".to_string(),
            key_file: "/tmp/key.pem".to_string(),
        },
    }
}

#[test]
fn test_runtime_config_from_service_config() {
    let config =
        EdgeRuntimeConfig::try_from(sample_service_config()).expect("service config should convert");

    assert_eq!(config.listen_addr, "127.0.0.1:9081");
    assert_eq!(config.tls_listen_addr, Some("127.0.0.1:9444".to_string()));
    assert_eq!(config.tls_cert_file, Some("/tmp/cert.pem".to_string()));
    assert_eq!(config.tls_key_file, Some("/tmp/key.pem".to_string()));
    assert_eq!(config.upstream_host, "127.0.0.1");
    assert_eq!(config.upstream_port, 9080);
    assert_eq!(
        config.allowed_hosts,
        vec!["allowed.local".to_string(), "legacy.local".to_string()]
    );
    assert_eq!(
        config.passthrough_hosts,
        vec!["passthrough.local".to_string()]
    );
    assert_eq!(config.canonical_host, Some("allowed.local".to_string()));
    assert_eq!(config.trusted_proxy_rules.len(), 1);
    assert_eq!(config.admin_allowed_rules.len(), 2);
    assert_eq!(config.blocked_rules.len(), 2);
    assert_eq!(
        config.admin_path_prefixes,
        vec!["/metrics".to_string(), "/ops".to_string()]
    );
    assert_eq!(config.upload_path_prefixes, vec!["/upload".to_string()]);
    assert_eq!(
        config.strict_rate_limit_path_prefixes,
        vec!["/login".to_string(), "/search".to_string()]
    );
    assert_eq!(
        config.thumb_path_prefixes,
        vec!["/thumb".to_string(), "/thumbserver".to_string()]
    );
    assert_eq!(config.gone_paths, vec!["/deprecated-endpoint".to_string()]);
    assert_eq!(config.max_body_bytes, Some(1024));
    assert_eq!(config.upload_max_body_bytes, Some(10 * 1024 * 1024));
    assert_eq!(config.downstream_read_timeout, Some(Duration::from_secs(5)));
    assert_eq!(
        config.upload_downstream_read_timeout,
        Some(Duration::from_secs(60))
    );
    assert_eq!(config.upstream_connect_timeout, Some(Duration::from_secs(3)));
    assert_eq!(config.upstream_read_timeout, Some(Duration::from_secs(30)));
    assert_eq!(
        config.upload_upstream_read_timeout,
        Some(Duration::from_secs(60))
    );
    assert_eq!(config.rate_limit_requests_per_minute, Some(60));
    assert_eq!(config.upload_rate_limit_requests_per_minute, Some(20));
    assert_eq!(config.thumb_rate_limit_requests_per_minute, Some(45));
    assert_eq!(config.strict_rate_limit_requests_per_minute, Some(30));
}

#[test]
fn test_runtime_config_rejects_invalid_admin_rules() {
    let mut config = sample_service_config();
    config.admin_allowed_ips = vec!["not-an-ip".to_string()];

    let result = EdgeRuntimeConfig::try_from(config);
    assert!(result.is_err());
}

#[test]
fn test_normalize_host_strips_port_and_case() {
    assert_eq!(normalize_host("WWW.WOLCHUCK.CC:443"), "www.wolchuck.cc");
    assert_eq!(normalize_host("[2001:db8::1]:443"), "[2001:db8::1]");
}
