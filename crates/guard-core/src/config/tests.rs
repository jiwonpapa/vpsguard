//! 설정 계약 회귀 테스트입니다.

#![allow(clippy::expect_used)]

use std::net::IpAddr;

use super::{
    AdminAuthProvider, AdminRole, ConfigError, CspMode, DetectionProfile, FirewallMode,
    GuardConfig, InspectionMode, ServiceCollectorKind, TlsManagementMode, UiTlsTermination,
};
use crate::crawler::CrawlerProvider;

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
    assert_eq!(config.cloudflare.max_dns_ttl_seconds, 300);
    assert!(!config.notifications.enabled);
    assert_eq!(config.notifications.queue_capacity, 256);
    assert_eq!(config.notifications.max_attempts, 3);
    assert_eq!(config.detection.profile, DetectionProfile::Gnuboard5);
    assert_eq!(config.detection.inspection, InspectionMode::Profiled);
    assert!(config.security.baseline_response_headers);
    assert!(config.security.strip_origin_headers);
    assert_eq!(config.security.csp_mode, CspMode::ReportOnly);
    assert_eq!(config.security.auth_rate_limit_rpm, 10);
    assert_eq!(config.ui.tls_termination, UiTlsTermination::Edge);
    assert_eq!(config.ui.auth_provider, AdminAuthProvider::Local);
    assert_eq!(config.firewall.mode, FirewallMode::Disabled);
    assert_eq!(config.firewall.ssh_port, 22);
    assert_eq!(config.edge.prefix_rate_limit_multiplier, 32);
    assert_eq!(config.edge.route_rate_limit_multiplier, 128);
    assert_eq!(config.edge.global_rate_limit_multiplier, 256);
    assert_eq!(config.edge.worker_threads, None);
    assert_eq!(config.edge.max_in_flight_requests, 1_024);
    assert_eq!(config.edge.downstream_io_timeout_ms, 30_000);
    assert_eq!(config.edge.downstream_min_send_rate_bps, 1_024);
    assert_eq!(config.edge.keepalive_request_limit, 1_000);
    assert_eq!(config.retention.audit_days, 365);
    assert_eq!(config.storage.max_database_bytes, 512 * 1_024 * 1_024);
    assert_eq!(config.storage.min_disk_free_bytes, 256 * 1_024 * 1_024);
}

#[test]
fn validates_bounded_https_notification_settings() {
    let valid = VALID_CONFIG.replace(
        "[retention]",
        "[notifications]\nenabled = true\nwebhook_url = \"https://alerts.example.test/vpsguard\"\ntoken_file = \"notification-webhook-token\"\nqueue_capacity = 64\nmax_attempts = 3\ninitial_backoff_ms = 100\nrequest_timeout_ms = 1000\n\n[retention]",
    );
    let config = GuardConfig::from_toml(&valid).expect("HTTPS notification should parse");
    assert!(config.notifications.enabled);
    assert_eq!(config.notifications.queue_capacity, 64);

    for (setting, expected_field) in [
        (
            "webhook_url = \"http://alerts.example.test/vpsguard\"",
            "notifications.webhook_url",
        ),
        (
            "webhook_url = \"https://token@alerts.example.test/vpsguard\"",
            "notifications.webhook_url",
        ),
        (
            "webhook_url = \"https://alerts.example.test/vpsguard?token=secret\"",
            "notifications.webhook_url",
        ),
        ("queue_capacity = 0", "notifications.queue_capacity"),
        ("max_attempts = 0", "notifications.max_attempts"),
        (
            "request_timeout_ms = 30001",
            "notifications.request_timeout_ms",
        ),
    ] {
        let input = match expected_field {
            "notifications.webhook_url" => valid.replace(
                "webhook_url = \"https://alerts.example.test/vpsguard\"",
                setting,
            ),
            "notifications.queue_capacity" => valid.replace("queue_capacity = 64", setting),
            "notifications.max_attempts" => valid.replace("max_attempts = 3", setting),
            _ => valid.replace("request_timeout_ms = 1000", setting),
        };
        assert!(matches!(
            GuardConfig::from_toml(&input),
            Err(ConfigError::Invalid { field, .. }) if field == expected_field
        ));
    }
}

#[test]
fn rejects_unbounded_downstream_resource_settings() {
    for (field, setting) in [
        ("edge.worker_threads", "worker_threads = 0"),
        ("edge.worker_threads", "worker_threads = 9"),
        ("edge.max_in_flight_requests", "max_in_flight_requests = 0"),
        (
            "edge.downstream_io_timeout_ms",
            "downstream_io_timeout_ms = 0",
        ),
        (
            "edge.downstream_min_send_rate_bps",
            "downstream_min_send_rate_bps = 0",
        ),
        (
            "edge.keepalive_request_limit",
            "keepalive_request_limit = 0",
        ),
    ] {
        let input = VALID_CONFIG.replace(
            "max_tracked_clients = 10000",
            &format!("max_tracked_clients = 10000\n{setting}"),
        );
        assert!(matches!(
            GuardConfig::from_toml(&input),
            Err(ConfigError::Invalid {
                field: actual,
                ..
            }) if actual == field
        ));
    }
}

#[test]
fn accepts_bounded_explicit_edge_worker_count() {
    let input = VALID_CONFIG.replace(
        "max_tracked_clients = 10000",
        "max_tracked_clients = 10000\nworker_threads = 2",
    );
    let config = GuardConfig::from_toml(&input).expect("bounded worker count should parse");

    assert_eq!(config.edge.worker_threads, Some(2));
}

#[test]
fn accepts_trusted_external_tls_management_host_without_edge_https() {
    let input = VALID_CONFIG.replace(
        "bind = \"127.0.0.1:7727\"",
        "bind = \"127.0.0.1:7727\"\npublic_host = \"vpsguard.gnuboard5.local\"\ntls_termination = \"trusted_external\"",
    );
    let config = GuardConfig::from_toml(&input).expect("trusted Apache TLS should parse");
    assert_eq!(config.ui.tls_termination, UiTlsTermination::TrustedExternal);
}

#[test]
fn external_tls_management_requires_a_trusted_loopback_peer() {
    let input = VALID_CONFIG
        .replace("trusted_proxy_cidrs = [\"127.0.0.1/32\"]", "trusted_proxy_cidrs = []")
        .replace(
            "bind = \"127.0.0.1:7727\"",
            "bind = \"127.0.0.1:7727\"\npublic_host = \"vpsguard.gnuboard5.local\"\ntls_termination = \"trusted_external\"",
        );
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "ui.tls_termination",
            ..
        })
    ));
}

#[test]
fn validates_pam_authentication_and_firewall_ownership() {
    let input = VALID_CONFIG
        .replace(
            "bind = \"127.0.0.1:7727\"",
            "bind = \"127.0.0.1:7727\"\nauth_provider = \"pam\"\npam_service = \"vps-guard\"\npam_allowed_group = \"vpsguard-admin\"",
        )
        .replace(
            "[detection]",
            "[firewall]\nmode = \"jw_agent_delegated\"\nssh_port = 2222\n\n[detection]",
        );
    let config = GuardConfig::from_toml(&input).expect("PAM and delegated firewall should parse");
    assert_eq!(config.ui.auth_provider, AdminAuthProvider::Pam);
    assert_eq!(config.firewall.mode, FirewallMode::JwAgentDelegated);
    assert_eq!(config.firewall.ssh_port, 2222);

    let root_group = input.replace(
        "pam_allowed_group = \"vpsguard-admin\"",
        "pam_allowed_group = \"root\"",
    );
    assert!(matches!(
        GuardConfig::from_toml(&root_group),
        Err(ConfigError::Invalid {
            field: "ui.pam_allowed_group",
            ..
        })
    ));
}

#[test]
fn validates_typed_ui_role_bindings() {
    let input = VALID_CONFIG.replace(
        "language = \"ko\"",
        "language = \"ko\"\nrole_bindings = [{ actor = \"audit.user\", role = \"analyst\" }, { actor = \"ops-user\", role = \"operator\" }]",
    );
    let config = GuardConfig::from_toml(&input).expect("role bindings should parse");
    assert_eq!(config.ui.role_bindings.len(), 2);
    assert_eq!(config.ui.role_bindings[0].role, AdminRole::Analyst);
    assert!(config.ui.role_bindings[0].role.can_view_raw_ip());
    assert!(config.ui.role_bindings[0].role.can_export_sensitive());
    assert!(!config.ui.role_bindings[0].role.can_operate());
    assert!(config.ui.role_bindings[1].role.can_operate());
    assert!(!config.ui.role_bindings[1].role.can_export_sensitive());

    for actor in ["audit.user", "break-glass", "root"] {
        let invalid = input.replace("ops-user", actor);
        assert!(matches!(
            GuardConfig::from_toml(&invalid),
            Err(ConfigError::Invalid {
                field: "ui.role_bindings",
                ..
            })
        ));
    }
}

#[test]
fn validates_declared_bot_policy_with_official_crawler_networks() {
    let input = VALID_CONFIG.replace(
        "[detection]",
        "[bot_policy]\nblock_unapproved_declared_bots = true\nallowed_crawlers = [\"google\", \"naver\", \"bing\"]\n\n[[bot_policy.crawler_networks]]\nprovider = \"google\"\ncidrs = [\"66.249.64.0/19\"]\n\n[[bot_policy.crawler_networks]]\nprovider = \"naver\"\ncidrs = [\"125.209.192.0/18\"]\n\n[[bot_policy.crawler_networks]]\nprovider = \"bing\"\ncidrs = [\"157.55.0.0/16\"]\n\n[detection]",
    );
    let config = GuardConfig::from_toml(&input).expect("verified crawler policy should parse");
    assert!(config.bot_policy.block_unapproved_declared_bots);
    assert!(
        config
            .bot_policy
            .allowed_crawlers
            .contains(&CrawlerProvider::Google)
    );

    let missing_network = input.replace(
        "allowed_crawlers = [\"google\", \"naver\", \"bing\"]",
        "allowed_crawlers = [\"google\", \"naver\", \"bing\", \"google\"]",
    );
    assert!(matches!(
        GuardConfig::from_toml(&missing_network),
        Err(ConfigError::Invalid {
            field: "bot_policy.allowed_crawlers",
            ..
        })
    ));
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
fn cloudflare_dns_ttl_policy_is_bounded() {
    let base = VALID_CONFIG.replace(
        "allowed_hosts = [\"g7devops.com\", \"*.g7devops.com\"]",
        "allowed_hosts = [\"g7devops.com\"]",
    );
    let provider = cloudflare_config(
        &[("11111111111111111111111111111111", "g7devops.com", "A")],
        "[\"192.0.2.0/24\", \"2001:db8::/32\"]",
    )
    .replace(
        "enabled = true",
        "enabled = true\nmax_dns_ttl_seconds = 3601",
    );
    let input = format!("{base}\n{provider}");
    assert!(matches!(
        GuardConfig::from_toml(&input),
        Err(ConfigError::Invalid {
            field: "cloudflare.max_dns_ttl_seconds",
            ..
        })
    ));
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
