use std::time::Duration;

use anyhow::Result;
use common::config::EdgeProxyConfig as EdgeProxyServiceConfig;
use common::network::{AllowedIpRule, parse_allowed_ip_rules};

#[derive(Debug, Clone)]
pub(crate) struct EdgeRuntimeConfig {
    pub(crate) listen_addr: String,
    pub(crate) tls_listen_addr: Option<String>,
    pub(crate) tls_cert_file: Option<String>,
    pub(crate) tls_key_file: Option<String>,
    pub(crate) upstream_host: String,
    pub(crate) upstream_port: u16,
    pub(crate) upstream_tls: bool,
    pub(crate) upstream_sni: String,
    pub(crate) allowed_hosts: Vec<String>,
    pub(crate) passthrough_hosts: Vec<String>,
    pub(crate) canonical_host: Option<String>,
    pub(crate) admin_allowed_rules: Vec<AllowedIpRule>,
    pub(crate) blocked_rules: Vec<AllowedIpRule>,
    pub(crate) trusted_proxy_rules: Vec<AllowedIpRule>,
    pub(crate) admin_path_prefixes: Vec<String>,
    pub(crate) upload_path_prefixes: Vec<String>,
    pub(crate) thumb_path_prefixes: Vec<String>,
    pub(crate) strict_rate_limit_path_prefixes: Vec<String>,
    pub(crate) gone_paths: Vec<String>,
    pub(crate) request_id_header: String,
    pub(crate) max_body_bytes: Option<u64>,
    pub(crate) upload_max_body_bytes: Option<u64>,
    pub(crate) downstream_read_timeout: Option<Duration>,
    pub(crate) upload_downstream_read_timeout: Option<Duration>,
    pub(crate) downstream_write_timeout: Option<Duration>,
    pub(crate) downstream_total_drain_timeout: Option<Duration>,
    pub(crate) upstream_connect_timeout: Option<Duration>,
    pub(crate) upstream_read_timeout: Option<Duration>,
    pub(crate) upload_upstream_read_timeout: Option<Duration>,
    pub(crate) upstream_write_timeout: Option<Duration>,
    pub(crate) upstream_idle_timeout: Option<Duration>,
    pub(crate) rate_limit_requests_per_minute: Option<u32>,
    pub(crate) upload_rate_limit_requests_per_minute: Option<u32>,
    pub(crate) thumb_rate_limit_requests_per_minute: Option<u32>,
    pub(crate) strict_rate_limit_requests_per_minute: Option<u32>,
}

impl TryFrom<EdgeProxyServiceConfig> for EdgeRuntimeConfig {
    type Error = anyhow::Error;

    fn try_from(value: EdgeProxyServiceConfig) -> Result<Self> {
        let admin_rules = parse_allowed_ip_rules(&value.admin_allowed_ips);
        let configured_admin_rule_count = value
            .admin_allowed_ips
            .iter()
            .filter(|raw| !raw.trim().is_empty())
            .count();

        if admin_rules.len() != configured_admin_rule_count {
            anyhow::bail!("edge_proxy.admin_allowed_ips에 잘못된 규칙이 있습니다");
        }

        let blocked_rules = parse_allowed_ip_rules(
            &value
                .blocked_ips
                .iter()
                .chain(value.blocked_cidrs.iter())
                .cloned()
                .collect::<Vec<_>>(),
        );
        let configured_blocked_rule_count = value
            .blocked_ips
            .iter()
            .chain(value.blocked_cidrs.iter())
            .filter(|raw| !raw.trim().is_empty())
            .count();

        if blocked_rules.len() != configured_blocked_rule_count {
            anyhow::bail!(
                "edge_proxy.blocked_ips 또는 edge_proxy.blocked_cidrs에 잘못된 규칙이 있습니다"
            );
        }

        let trusted_proxy_rules = parse_allowed_ip_rules(&value.trusted_proxy_cidrs);
        let configured_trusted_proxy_rule_count = value
            .trusted_proxy_cidrs
            .iter()
            .filter(|raw| !raw.trim().is_empty())
            .count();

        if trusted_proxy_rules.len() != configured_trusted_proxy_rule_count {
            anyhow::bail!("edge_proxy.trusted_proxy_cidrs에 잘못된 규칙이 있습니다");
        }

        let canonical_host = normalize_host(&value.canonical_host);

        Ok(Self {
            listen_addr: format!("{}:{}", value.bind_address.trim(), value.port),
            tls_listen_addr: value.tls_listener.enabled.then(|| {
                format!(
                    "{}:{}",
                    value.tls_listener.bind_address.trim(),
                    value.tls_listener.port
                )
            }),
            tls_cert_file: value
                .tls_listener
                .enabled
                .then(|| value.tls_listener.cert_file.trim().to_string()),
            tls_key_file: value
                .tls_listener
                .enabled
                .then(|| value.tls_listener.key_file.trim().to_string()),
            upstream_host: value.upstream_host.trim().to_string(),
            upstream_port: value.upstream_port,
            upstream_tls: value.upstream_tls,
            upstream_sni: value.upstream_sni.trim().to_string(),
            allowed_hosts: value
                .allowed_hosts
                .into_iter()
                .map(|item| normalize_host(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            passthrough_hosts: value
                .passthrough_hosts
                .into_iter()
                .map(|item| normalize_host(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            canonical_host: (!canonical_host.is_empty()).then_some(canonical_host),
            admin_allowed_rules: admin_rules,
            blocked_rules,
            trusted_proxy_rules,
            admin_path_prefixes: value
                .admin_path_prefixes
                .into_iter()
                .map(|item| normalize_path_rule(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            upload_path_prefixes: value
                .upload_path_prefixes
                .into_iter()
                .map(|item| normalize_path_rule(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            thumb_path_prefixes: value
                .thumb_path_prefixes
                .into_iter()
                .map(|item| normalize_path_rule(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            strict_rate_limit_path_prefixes: value
                .strict_rate_limit_path_prefixes
                .into_iter()
                .map(|item| normalize_path_rule(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            gone_paths: value
                .gone_paths
                .into_iter()
                .map(|item| normalize_path_rule(&item))
                .filter(|item| !item.is_empty())
                .collect(),
            request_id_header: value.request_id_header.trim().to_string(),
            max_body_bytes: value.max_body_bytes,
            upload_max_body_bytes: value.upload_max_body_bytes,
            downstream_read_timeout: option_millis_to_duration(value.downstream_read_timeout_ms),
            upload_downstream_read_timeout: option_millis_to_duration(
                value.upload_downstream_read_timeout_ms,
            ),
            downstream_write_timeout: option_millis_to_duration(value.downstream_write_timeout_ms),
            downstream_total_drain_timeout: option_millis_to_duration(
                value.downstream_total_drain_timeout_ms,
            ),
            upstream_connect_timeout: option_millis_to_duration(value.upstream_connect_timeout_ms),
            upstream_read_timeout: option_millis_to_duration(value.upstream_read_timeout_ms),
            upload_upstream_read_timeout: option_millis_to_duration(
                value.upload_upstream_read_timeout_ms,
            ),
            upstream_write_timeout: option_millis_to_duration(value.upstream_write_timeout_ms),
            upstream_idle_timeout: option_millis_to_duration(value.upstream_idle_timeout_ms),
            rate_limit_requests_per_minute: value.rate_limit_requests_per_minute,
            upload_rate_limit_requests_per_minute: value.upload_rate_limit_requests_per_minute,
            thumb_rate_limit_requests_per_minute: value.thumb_rate_limit_requests_per_minute,
            strict_rate_limit_requests_per_minute: value.strict_rate_limit_requests_per_minute,
        })
    }
}

fn option_millis_to_duration(value: Option<u64>) -> Option<Duration> {
    value.map(Duration::from_millis)
}

pub(crate) fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with('[') {
        return trimmed
            .find(']')
            .map(|index| trimmed[..=index].to_ascii_lowercase())
            .unwrap_or_else(|| trimmed.to_ascii_lowercase());
    }

    trimmed
        .split(':')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

pub(crate) fn normalize_path_rule(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed == "/" {
        return "/".to_string();
    }
    let with_leading_slash = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    with_leading_slash.trim_end_matches('/').to_string()
}
