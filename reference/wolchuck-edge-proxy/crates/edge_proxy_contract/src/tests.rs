use super::*;

#[test]
fn test_edge_proxy_config_derive_defaults() {
    let config = EdgeProxyConfig::default();
    assert!(!config.enabled);
    assert!(config.bind_address.is_empty());
    assert_eq!(config.port, 0);
    assert_eq!(config.upstream_port, 0);
    assert!(config.request_id_header.is_empty());
    assert!(config.max_body_bytes.is_none());
    assert!(config.rate_limit_requests_per_minute.is_none());
    assert!(config.upload_max_body_bytes.is_none());
    assert!(config.upload_rate_limit_requests_per_minute.is_none());
    assert!(config.thumb_rate_limit_requests_per_minute.is_none());
    assert!(config.strict_rate_limit_requests_per_minute.is_none());
    assert!(config.downstream_read_timeout_ms.is_none());
    assert!(config.upload_downstream_read_timeout_ms.is_none());
    assert!(config.downstream_write_timeout_ms.is_none());
    assert!(config.downstream_total_drain_timeout_ms.is_none());
    assert!(config.upstream_connect_timeout_ms.is_none());
    assert!(config.upstream_read_timeout_ms.is_none());
    assert!(config.upload_upstream_read_timeout_ms.is_none());
    assert!(config.upstream_write_timeout_ms.is_none());
    assert!(config.upstream_idle_timeout_ms.is_none());
    assert!(config.blocked_ips.is_empty());
    assert!(config.blocked_cidrs.is_empty());
    assert!(config.trusted_proxy_cidrs.is_empty());
    assert!(config.admin_path_prefixes.is_empty());
    assert!(config.upload_path_prefixes.is_empty());
    assert!(config.thumb_path_prefixes.is_empty());
    assert!(config.strict_rate_limit_path_prefixes.is_empty());
    assert!(config.gone_paths.is_empty());
    assert!(!config.tls_listener.enabled);
    assert_eq!(config.tls_listener.port, 0);
}

#[test]
fn test_edge_proxy_config_serde_defaults() {
    let config: EdgeProxyConfig = serde_yaml::from_str("{}").expect("empty yaml should parse");
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 9081);
    assert_eq!(config.upstream_host, "127.0.0.1");
    assert_eq!(config.upstream_port, 9080);
    assert!(!config.upstream_tls);
    assert_eq!(config.upstream_sni, "irongate");
    assert_eq!(config.request_id_header, "x-request-id");
    assert!(config.blocked_ips.is_empty());
    assert!(config.blocked_cidrs.is_empty());
    assert!(config.trusted_proxy_cidrs.is_empty());
    assert!(config.admin_path_prefixes.is_empty());
    assert!(config.upload_path_prefixes.is_empty());
    assert!(config.thumb_path_prefixes.is_empty());
    assert!(config.strict_rate_limit_path_prefixes.is_empty());
    assert!(config.gone_paths.is_empty());
    assert!(config.upload_max_body_bytes.is_none());
    assert!(config.upload_rate_limit_requests_per_minute.is_none());
    assert!(config.thumb_rate_limit_requests_per_minute.is_none());
    assert!(config.strict_rate_limit_requests_per_minute.is_none());
    assert!(config.downstream_read_timeout_ms.is_none());
    assert!(config.upload_downstream_read_timeout_ms.is_none());
    assert!(config.downstream_write_timeout_ms.is_none());
    assert!(config.downstream_total_drain_timeout_ms.is_none());
    assert!(config.upstream_connect_timeout_ms.is_none());
    assert!(config.upstream_read_timeout_ms.is_none());
    assert!(config.upload_upstream_read_timeout_ms.is_none());
    assert!(config.upstream_write_timeout_ms.is_none());
    assert!(config.upstream_idle_timeout_ms.is_none());
    assert!(!config.tls_listener.enabled);
    assert_eq!(config.tls_listener.bind_address, "0.0.0.0");
    assert_eq!(config.tls_listener.port, 443);
}

#[test]
fn test_edge_proxy_config_validate_rejects_invalid_admin_ip() {
    let config = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        admin_allowed_ips: vec!["nope".to_string()],
        ..Default::default()
    };

    let err = config.validate().expect_err("invalid admin ip should fail");
    assert!(err.contains("admin_allowed_ips"));
}

#[test]
fn test_edge_proxy_config_validate_rejects_invalid_trusted_proxy_ip() {
    let config = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        trusted_proxy_cidrs: vec!["bad-cidr".to_string()],
        ..Default::default()
    };

    let err = config
        .validate()
        .expect_err("invalid trusted proxy ip should fail");
    assert!(err.contains("trusted_proxy_cidrs"));
}

#[test]
fn test_edge_proxy_config_validate_rejects_invalid_block_rules() {
    let blocked_ip = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        blocked_ips: vec!["nope".to_string()],
        ..Default::default()
    };
    assert!(blocked_ip.validate().is_err());

    let blocked_cidr = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        blocked_cidrs: vec!["bad-cidr".to_string()],
        ..Default::default()
    };
    assert!(blocked_cidr.validate().is_err());
}

#[test]
fn test_edge_proxy_config_validate_rejects_zero_optional_limits() {
    let body_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        max_body_bytes: Some(0),
        ..Default::default()
    };
    assert!(body_limit.validate().is_err());

    let rate_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        rate_limit_requests_per_minute: Some(0),
        ..Default::default()
    };
    assert!(rate_limit.validate().is_err());

    let upload_body_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        upload_max_body_bytes: Some(0),
        ..Default::default()
    };
    assert!(upload_body_limit.validate().is_err());

    let upload_rate_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        upload_rate_limit_requests_per_minute: Some(0),
        ..Default::default()
    };
    assert!(upload_rate_limit.validate().is_err());

    let thumb_rate_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        thumb_rate_limit_requests_per_minute: Some(0),
        ..Default::default()
    };
    assert!(thumb_rate_limit.validate().is_err());

    let strict_rate_limit = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        strict_rate_limit_requests_per_minute: Some(0),
        ..Default::default()
    };
    assert!(strict_rate_limit.validate().is_err());

    let downstream_timeout = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        downstream_read_timeout_ms: Some(0),
        ..Default::default()
    };
    assert!(downstream_timeout.validate().is_err());
}

#[test]
fn test_edge_proxy_config_validate_rejects_upload_limit_smaller_than_default() {
    let config = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        max_body_bytes: Some(1024),
        upload_max_body_bytes: Some(512),
        ..Default::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn test_edge_proxy_config_validate_rejects_invalid_path_rules() {
    let admin_paths = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        admin_path_prefixes: vec!["metrics".to_string()],
        ..Default::default()
    };
    assert!(admin_paths.validate().is_err());

    let gone_paths = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        gone_paths: vec!["deprecated".to_string()],
        ..Default::default()
    };
    assert!(gone_paths.validate().is_err());

    let upload_paths = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        upload_path_prefixes: vec!["upload".to_string()],
        ..Default::default()
    };
    assert!(upload_paths.validate().is_err());

    let thumb_paths = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        thumb_path_prefixes: vec!["thumb".to_string()],
        ..Default::default()
    };
    assert!(thumb_paths.validate().is_err());

    let strict_rate_limit_paths = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        strict_rate_limit_path_prefixes: vec!["login".to_string()],
        ..Default::default()
    };
    assert!(strict_rate_limit_paths.validate().is_err());
}

#[test]
fn test_edge_proxy_config_validate_accepts_tls_listener() {
    let config = EdgeProxyConfig {
        enabled: true,
        bind_address: "127.0.0.1".to_string(),
        port: 9081,
        upstream_host: "127.0.0.1".to_string(),
        upstream_port: 9080,
        request_id_header: "x-request-id".to_string(),
        tls_listener: EdgeProxyTlsListenerConfig {
            enabled: true,
            bind_address: "0.0.0.0".to_string(),
            port: 443,
            cert_file: "/tmp/cert.pem".to_string(),
            key_file: "/tmp/key.pem".to_string(),
        },
        ..Default::default()
    };

    assert!(config.validate().is_ok());
}
