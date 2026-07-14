//! 설정 계약 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;

use super::{ConfigError, GuardConfig};

const VALID_CONFIG: &str = r#"
schema_version = 1

[edge]
http_bind = "127.0.0.1:18080"
allowed_hosts = ["g7devops.com", "*.g7devops.com"]
canonical_host = "g7devops.com"
trusted_proxy_cidrs = ["127.0.0.1/32"]
max_body_bytes = 1048576
upload_max_body_bytes = 52428800
upload_path_prefixes = ["/upload"]
strict_path_prefixes = ["/login", "/search"]
upstream_connect_timeout_ms = 3000
upstream_read_timeout_ms = 30000
upload_upstream_read_timeout_ms = 60000
max_tracked_clients = 10000

[origin]
address = "127.0.0.1:18081"
protocol = "http"

[ui]
bind = "127.0.0.1:7727"
language = "ko"

[detection]
profile = "gnuboard"
mode = "observe"

[retention]
live_seconds = 900
detail_hours = 24
aggregate_days = 30
incident_days = 90
raw_ip_days = 7
"#;

#[test]
fn parses_valid_observe_only_config() {
    let config = GuardConfig::from_toml(VALID_CONFIG).expect("valid config should parse");
    assert_eq!(config.edge.http_bind.to_string(), "127.0.0.1:18080");
    assert!(config.tls.certificates.is_empty());
    assert!(!config.cloudflare.enabled);
}

#[test]
fn rejects_unknown_fields() {
    let input = VALID_CONFIG.replace("max_tracked_clients = 10000", "unknown = true");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn rejects_future_schema() {
    let input = VALID_CONFIG.replace("schema_version = 1", "schema_version = 2");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::UnsupportedSchema { actual: 2, .. })
    ));
}

#[test]
fn rejects_public_ui_bind() {
    let input = VALID_CONFIG.replace("127.0.0.1:7727", "0.0.0.0:7727");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "ui.bind",
            ..
        })
    ));
}

#[test]
fn rejects_unbounded_client_tracking() {
    let input = VALID_CONFIG.replace("max_tracked_clients = 10000", "max_tracked_clients = 0");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "edge.max_tracked_clients",
            ..
        })
    ));
}

#[test]
fn rejects_https_without_certificate() {
    let input = VALID_CONFIG.replace(
        "http_bind = \"127.0.0.1:18080\"",
        "http_bind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"",
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "tls.certificates",
            ..
        })
    ));
}

#[test]
fn only_trusts_configured_forwarded_peer() {
    let config = GuardConfig::from_toml(VALID_CONFIG).expect("valid config should parse");
    let loopback = "127.0.0.1".parse::<IpAddr>().expect("valid fixture IP");
    let public = "203.0.113.10".parse::<IpAddr>().expect("valid fixture IP");
    assert!(config.trusts_forwarded_peer(loopback));
    assert!(!config.trusts_forwarded_peer(public));
}
