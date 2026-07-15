//! 설정 계약 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;

use super::{
    ConfigError, CspMode, DetectionProfile, GuardConfig, InspectionMode, ServiceCollectorKind,
    TlsManagementMode,
};

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
strict_rate_limit_rpm = 60
upload_rate_limit_rpm = 30

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
    assert_eq!(config.tls.management, TlsManagementMode::Auto);
    assert!(!config.cloudflare.enabled);
    assert_eq!(config.detection.profile, DetectionProfile::Gnuboard5);
    assert_eq!(config.detection.inspection, InspectionMode::Profiled);
    assert!(config.security.baseline_response_headers);
    assert!(config.security.strip_origin_headers);
    assert_eq!(config.security.csp_mode, CspMode::ReportOnly);
    assert_eq!(config.security.auth_rate_limit_rpm, 10);
    assert_eq!(config.retention.audit_days, 365);
    assert_eq!(config.storage.max_database_bytes, 512 * 1_024 * 1_024);
    assert_eq!(config.storage.min_disk_free_bytes, 256 * 1_024 * 1_024);
}

#[test]
fn validates_typed_application_security_settings() {
    let valid = format!(
        "{VALID_CONFIG}\n[security]\ncsp_mode = \"enforce\"\ncsp_policy = \"default-src 'self'; object-src 'none'\"\nhsts_max_age_seconds = 31536000\nauth_rate_limit_rpm = 6\n"
    );
    let config = GuardConfig::from_toml(&valid).expect("security config should parse");
    assert_eq!(config.security.csp_mode, CspMode::Enforce);
    assert_eq!(config.security.hsts_max_age_seconds, 31_536_000);
    assert_eq!(config.security.auth_rate_limit_rpm, 6);

    let disabled_with_policy = format!(
        "{VALID_CONFIG}\n[security]\ncsp_mode = \"off\"\ncsp_policy = \"default-src 'self'\"\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&disabled_with_policy),
        Err(ConfigError::Invalid {
            field: "security.csp_policy",
            ..
        })
    ));

    let oversized_policy = "a".repeat(4_097);
    let oversized = format!(
        "{VALID_CONFIG}\n[security]\ncsp_mode = \"report_only\"\ncsp_policy = \"{oversized_policy}\"\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&oversized),
        Err(ConfigError::Invalid {
            field: "security.csp_policy",
            ..
        })
    ));

    let injected = format!(
        "{VALID_CONFIG}\n[security]\ncsp_mode = \"enforce\"\ncsp_policy = \"default-src 'self'\\r\\nx-injected: true\"\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&injected),
        Err(ConfigError::Invalid {
            field: "security.csp_policy",
            ..
        })
    ));

    let unsafe_limits = format!(
        "{VALID_CONFIG}\n[security]\nhsts_max_age_seconds = 63072001\nauth_rate_limit_rpm = 601\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&unsafe_limits),
        Err(ConfigError::Invalid {
            field: "security.hsts_max_age_seconds",
            ..
        })
    ));
}

#[test]
fn parses_protocol_only_independently_from_enforcement() {
    let source = VALID_CONFIG
        .replace(
            "profile = \"gnuboard\"",
            "profile = \"gnuboard\"\ninspection = \"protocol_only\"",
        )
        .replace("mode = \"observe\"", "mode = \"enforce\"");
    let config = GuardConfig::from_toml(&source).expect("protocol-only config should parse");
    assert_eq!(config.detection.inspection, InspectionMode::ProtocolOnly);
    assert_eq!(config.detection.mode, super::DetectionMode::Enforce);
}

#[test]
fn rejects_relative_storage_paths_and_unbounded_budget() {
    let relative = format!(
        "{VALID_CONFIG}\n[storage]\ndatabase_path = \"control.sqlite3\"\nevents_directory = \"/tmp/events\"\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&relative),
        Err(ConfigError::Invalid {
            field: "storage",
            ..
        })
    ));

    let oversized = format!(
        "{VALID_CONFIG}\n[storage]\ndatabase_path = \"/tmp/control.sqlite3\"\nevents_directory = \"/tmp/events\"\nmax_database_bytes = 17179869185\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&oversized),
        Err(ConfigError::Invalid {
            field: "storage.max_database_bytes",
            ..
        })
    ));
}

#[test]
fn rejects_unbounded_live_retention_ring() {
    let input = VALID_CONFIG.replace("live_seconds = 900", "live_seconds = 86401");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "retention.live_seconds",
            ..
        })
    ));
}

#[test]
fn parses_allowlisted_php_service_and_rejects_ssrf_or_cgroup_mismatch() {
    let valid = format!(
        "{VALID_CONFIG}\n[collectors]\ntimeout_ms = 500\n\n[[collectors.services]]\nname = \"php\"\nunit = \"php8.3-fpm.service\"\nkind = \"php_fpm\"\nstatus_url = \"http://127.0.0.1/fpm-status\"\n"
    );
    let config = GuardConfig::from_toml(&valid).expect("allowlisted service should parse");
    assert_eq!(
        config.collectors.services[0].kind,
        ServiceCollectorKind::PhpFpm
    );

    let remote = valid.replace(
        "status_url = \"http://127.0.0.1/fpm-status\"",
        "status_url = \"http://example.com/fpm-status\"",
    );
    assert!(matches!(
        GuardConfig::from_toml(&remote),
        Err(ConfigError::Invalid {
            field: "collectors.services.status_url",
            ..
        })
    ));

    let mismatch = valid.replace(
        "status_url = \"http://127.0.0.1/fpm-status\"",
        "status_url = \"http://127.0.0.1/fpm-status\"\ncgroup_path = \"system.slice/redis.service\"",
    );
    assert!(matches!(
        GuardConfig::from_toml(&mismatch),
        Err(ConfigError::Invalid {
            field: "collectors.services.cgroup_path",
            ..
        })
    ));
}

#[test]
fn mysql_service_requires_a_credential_file() {
    let input = format!(
        "{VALID_CONFIG}\n[collectors]\ntimeout_ms = 500\n\n[[collectors.services]]\nname = \"database\"\nunit = \"mysql.service\"\nkind = \"mysql\"\n"
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "collectors.services",
            ..
        })
    ));
}

#[test]
fn parses_explicit_gnuboard7_profile() {
    let input = VALID_CONFIG.replace("profile = \"gnuboard\"", "profile = \"gnuboard7\"");
    let config = GuardConfig::from_toml(&input).expect("GnuBoard 7 profile should parse");
    assert_eq!(config.detection.profile, DetectionProfile::Gnuboard7);
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
fn public_management_host_requires_https() {
    let input = VALID_CONFIG.replace(
        "bind = \"127.0.0.1:7727\"",
        "bind = \"127.0.0.1:7727\"\npublic_host = \"guard.g7devops.com\"",
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "ui.public_host",
            ..
        })
    ));
}

#[test]
fn public_management_host_must_be_covered_by_certificate() {
    let input = VALID_CONFIG
        .replace(
            "http_bind = \"127.0.0.1:18080\"",
            "http_bind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"",
        )
        .replace(
            "bind = \"127.0.0.1:7727\"",
            "bind = \"127.0.0.1:7727\"\npublic_host = \"guard.other.test\"",
        )
        .replace(
            "[ui]",
            "[tls]\n[[tls.certificates]]\ndomains = [\"*.g7devops.com\"]\ncert_file = \"/tmp/cert.pem\"\nkey_file = \"/tmp/key.pem\"\n\n[ui]",
        );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "ui.public_host",
            ..
        })
    ));
}

#[test]
fn accepts_separate_management_host_covered_by_wildcard_certificate() {
    let input = VALID_CONFIG
        .replace(
            "http_bind = \"127.0.0.1:18080\"",
            "http_bind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"",
        )
        .replace(
            "bind = \"127.0.0.1:7727\"",
            "bind = \"127.0.0.1:7727\"\npublic_host = \"guard.g7devops.com\"",
        )
        .replace(
            "[ui]",
            "[tls]\n[[tls.certificates]]\ndomains = [\"*.g7devops.com\"]\ncert_file = \"/tmp/cert.pem\"\nkey_file = \"/tmp/key.pem\"\n\n[ui]",
        );
    assert!(GuardConfig::from_toml(&input).is_ok());
}

#[test]
fn parses_external_tls_management_with_credential_names() {
    let input = VALID_CONFIG.replace(
        "[ui]",
        "[tls]\nmanagement = \"external_managed\"\n[[tls.certificates]]\ndomains = [\"g7devops.com\"]\ncert_file = \"tls-cert.pem\"\nkey_file = \"tls-key.pem\"\n\n[ui]",
    );
    let config = GuardConfig::from_toml(&input).expect("external TLS management should parse");
    assert_eq!(config.tls.management, TlsManagementMode::ExternalManaged);
    assert_eq!(
        config.tls.certificates[0].cert_file,
        std::path::Path::new("tls-cert.pem")
    );
}

#[test]
fn rejects_tls_credential_path_traversal() {
    let input = VALID_CONFIG.replace(
        "[ui]",
        "[tls]\n[[tls.certificates]]\ndomains = [\"g7devops.com\"]\ncert_file = \"../tls-cert.pem\"\nkey_file = \"tls-key.pem\"\n\n[ui]",
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "tls.certificates.cert_file",
            ..
        })
    ));
}

#[test]
fn rejects_certbot_lineage_path_traversal() {
    let input = VALID_CONFIG.replace(
        "[ui]",
        "[tls]\n[[tls.certificates]]\ndomains = [\"g7devops.com\"]\ncert_file = \"tls-cert.pem\"\nkey_file = \"tls-key.pem\"\ncertbot_lineage = \"../example\"\n\n[ui]",
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "tls.certificates.certbot_lineage",
            ..
        })
    ));
}

#[test]
fn wildcard_certificate_does_not_cover_multiple_labels() {
    let input = VALID_CONFIG
        .replace(
            "http_bind = \"127.0.0.1:18080\"",
            "http_bind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"",
        )
        .replace(
            "bind = \"127.0.0.1:7727\"",
            "bind = \"127.0.0.1:7727\"\npublic_host = \"deep.guard.g7devops.com\"",
        )
        .replace(
            "[ui]",
            "[tls]\n[[tls.certificates]]\ndomains = [\"*.g7devops.com\"]\ncert_file = \"/tmp/cert.pem\"\nkey_file = \"/tmp/key.pem\"\n\n[ui]",
        );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "ui.public_host",
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

#[test]
fn cloudflare_rejects_records_for_multiple_hostnames() {
    let input = format!(
        "{VALID_CONFIG}\n{}",
        cloudflare_config(
            &[
                ("11111111111111111111111111111111", "example.com", "A"),
                (
                    "22222222222222222222222222222222",
                    "www.example.com",
                    "AAAA",
                ),
            ],
            "[\"192.0.2.0/24\", \"2001:db8::/32\"]"
        )
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "cloudflare.records",
            ..
        })
    ));
}

#[test]
fn cloudflare_origin_lock_requires_both_address_families() {
    let input = format!(
        "{VALID_CONFIG}\n{}",
        cloudflare_config(
            &[("11111111111111111111111111111111", "example.com", "A")],
            "[\"192.0.2.0/24\"]"
        )
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "cloudflare.ip_networks",
            ..
        })
    ));
}

#[test]
fn cloudflare_single_record_requires_one_served_hostname() {
    let input = format!(
        "{VALID_CONFIG}\n{}",
        cloudflare_config(
            &[("11111111111111111111111111111111", "g7devops.com", "A",)],
            "[\"192.0.2.0/24\", \"2001:db8::/32\"]"
        )
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "cloudflare.records",
            ..
        })
    ));
}

#[test]
fn accepts_single_hostname_multi_record_cloudflare_config() {
    let base = VALID_CONFIG.replace(
        "allowed_hosts = [\"g7devops.com\", \"*.g7devops.com\"]",
        "allowed_hosts = [\"g7devops.com\"]",
    );
    let input = format!(
        "{base}\n{}",
        cloudflare_config(
            &[
                ("11111111111111111111111111111111", "g7devops.com", "A",),
                ("22222222222222222222222222222222", "g7devops.com", "AAAA",),
            ],
            "[\"192.0.2.0/24\", \"2001:db8::/32\"]"
        )
    );
    assert!(GuardConfig::from_toml(&input).is_ok());
}

#[test]
fn rejects_duplicate_cloudflare_record_ids() {
    let base = VALID_CONFIG.replace(
        "allowed_hosts = [\"g7devops.com\", \"*.g7devops.com\"]",
        "allowed_hosts = [\"g7devops.com\"]",
    );
    let input = format!(
        "{base}\n{}",
        cloudflare_config(
            &[
                ("11111111111111111111111111111111", "g7devops.com", "A",),
                ("11111111111111111111111111111111", "g7devops.com", "AAAA",),
            ],
            "[\"192.0.2.0/24\", \"2001:db8::/32\"]"
        )
    );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "cloudflare.records",
            ..
        })
    ));
}

fn cloudflare_config(records: &[(&str, &str, &str)], networks: &str) -> String {
    let record_tables = records
        .iter()
        .map(|(id, name, record_type)| {
            format!(
                r#"
[[cloudflare.records]]
id = "{id}"
name = "{name}"
record_type = "{record_type}"
"#
            )
        })
        .collect::<String>();
    format!(
        r#"
[cloudflare]
enabled = true
zone_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
token_file = "/tmp/cloudflare-token"
ip_networks = {networks}
{record_tables}
"#
    )
}
