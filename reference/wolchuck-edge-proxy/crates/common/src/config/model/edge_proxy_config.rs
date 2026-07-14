use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EdgeProxyTlsListenerConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_tls_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_tls_port")]
    pub port: u16,

    #[serde(default)]
    pub cert_file: String,

    #[serde(default)]
    pub key_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EdgeProxyConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_edge_proxy_port")]
    pub port: u16,

    #[serde(default = "default_upstream_host")]
    pub upstream_host: String,

    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,

    #[serde(default)]
    pub upstream_tls: bool,

    #[serde(default = "default_upstream_sni")]
    pub upstream_sni: String,

    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    #[serde(default)]
    pub passthrough_hosts: Vec<String>,

    #[serde(default)]
    pub canonical_host: String,

    #[serde(default)]
    pub admin_allowed_ips: Vec<String>,

    #[serde(default)]
    pub blocked_ips: Vec<String>,

    #[serde(default)]
    pub blocked_cidrs: Vec<String>,

    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,

    #[serde(default)]
    pub admin_path_prefixes: Vec<String>,

    #[serde(default)]
    pub upload_path_prefixes: Vec<String>,

    #[serde(default)]
    pub thumb_path_prefixes: Vec<String>,

    #[serde(default)]
    pub strict_rate_limit_path_prefixes: Vec<String>,

    #[serde(default)]
    pub gone_paths: Vec<String>,

    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,

    #[serde(default)]
    pub max_body_bytes: Option<u64>,

    #[serde(default)]
    pub upload_max_body_bytes: Option<u64>,

    #[serde(default)]
    pub downstream_read_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upload_downstream_read_timeout_ms: Option<u64>,

    #[serde(default)]
    pub downstream_write_timeout_ms: Option<u64>,

    #[serde(default)]
    pub downstream_total_drain_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upstream_connect_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upstream_read_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upload_upstream_read_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upstream_write_timeout_ms: Option<u64>,

    #[serde(default)]
    pub upstream_idle_timeout_ms: Option<u64>,

    #[serde(default)]
    pub rate_limit_requests_per_minute: Option<u32>,

    #[serde(default)]
    pub upload_rate_limit_requests_per_minute: Option<u32>,

    #[serde(default)]
    pub thumb_rate_limit_requests_per_minute: Option<u32>,

    #[serde(default)]
    pub strict_rate_limit_requests_per_minute: Option<u32>,

    #[serde(default = "default_tls_listener_config")]
    pub tls_listener: EdgeProxyTlsListenerConfig,
}

impl EdgeProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.bind_address.trim().is_empty() {
            return Err("edge_proxy.bind_address is required".to_string());
        }
        if self.port == 0 {
            return Err("edge_proxy.port must be greater than 0".to_string());
        }
        if self.upstream_host.trim().is_empty() {
            return Err("edge_proxy.upstream_host is required".to_string());
        }
        if self.upstream_port == 0 {
            return Err("edge_proxy.upstream_port must be greater than 0".to_string());
        }
        if self.request_id_header.trim().is_empty() {
            return Err("edge_proxy.request_id_header is required".to_string());
        }
        if let Some(limit) = self.max_body_bytes
            && limit == 0
        {
            return Err("edge_proxy.max_body_bytes must be greater than 0".to_string());
        }
        if let Some(limit) = self.upload_max_body_bytes
            && limit == 0
        {
            return Err("edge_proxy.upload_max_body_bytes must be greater than 0".to_string());
        }
        if let (Some(default_limit), Some(upload_limit)) =
            (self.max_body_bytes, self.upload_max_body_bytes)
            && upload_limit < default_limit
        {
            return Err(
                "edge_proxy.upload_max_body_bytes must be greater than or equal to edge_proxy.max_body_bytes"
                    .to_string(),
            );
        }
        if let Some(limit) = self.rate_limit_requests_per_minute
            && limit == 0
        {
            return Err(
                "edge_proxy.rate_limit_requests_per_minute must be greater than 0".to_string(),
            );
        }
        if let Some(limit) = self.upload_rate_limit_requests_per_minute
            && limit == 0
        {
            return Err(
                "edge_proxy.upload_rate_limit_requests_per_minute must be greater than 0"
                    .to_string(),
            );
        }
        if let Some(limit) = self.thumb_rate_limit_requests_per_minute
            && limit == 0
        {
            return Err(
                "edge_proxy.thumb_rate_limit_requests_per_minute must be greater than 0"
                    .to_string(),
            );
        }
        if let Some(limit) = self.strict_rate_limit_requests_per_minute
            && limit == 0
        {
            return Err(
                "edge_proxy.strict_rate_limit_requests_per_minute must be greater than 0"
                    .to_string(),
            );
        }
        validate_optional_timeout(
            self.downstream_read_timeout_ms,
            "edge_proxy.downstream_read_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upload_downstream_read_timeout_ms,
            "edge_proxy.upload_downstream_read_timeout_ms",
        )?;
        validate_optional_timeout(
            self.downstream_write_timeout_ms,
            "edge_proxy.downstream_write_timeout_ms",
        )?;
        validate_optional_timeout(
            self.downstream_total_drain_timeout_ms,
            "edge_proxy.downstream_total_drain_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upstream_connect_timeout_ms,
            "edge_proxy.upstream_connect_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upstream_read_timeout_ms,
            "edge_proxy.upstream_read_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upload_upstream_read_timeout_ms,
            "edge_proxy.upload_upstream_read_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upstream_write_timeout_ms,
            "edge_proxy.upstream_write_timeout_ms",
        )?;
        validate_optional_timeout(
            self.upstream_idle_timeout_ms,
            "edge_proxy.upstream_idle_timeout_ms",
        )?;
        for host in &self.allowed_hosts {
            if host.trim().is_empty() {
                return Err("edge_proxy.allowed_hosts must not contain empty values".to_string());
            }
        }
        for host in &self.passthrough_hosts {
            if host.trim().is_empty() {
                return Err(
                    "edge_proxy.passthrough_hosts must not contain empty values".to_string()
                );
            }
        }
        if self.canonical_host.trim().is_empty() && !self.canonical_host.is_empty() {
            return Err("edge_proxy.canonical_host must not be whitespace only".to_string());
        }
        for raw in &self.admin_allowed_ips {
            if raw.parse::<IpAddr>().is_ok() || raw.parse::<IpNet>().is_ok() {
                continue;
            }
            return Err(format!(
                "edge_proxy.admin_allowed_ips contains invalid ip rule: {raw}"
            ));
        }
        for raw in &self.blocked_ips {
            if raw.parse::<IpAddr>().is_ok() {
                continue;
            }
            return Err(format!(
                "edge_proxy.blocked_ips contains invalid ip rule: {raw}"
            ));
        }
        for raw in &self.blocked_cidrs {
            if raw.parse::<IpNet>().is_ok() {
                continue;
            }
            return Err(format!(
                "edge_proxy.blocked_cidrs contains invalid ip rule: {raw}"
            ));
        }
        for raw in &self.trusted_proxy_cidrs {
            if raw.parse::<IpAddr>().is_ok() || raw.parse::<IpNet>().is_ok() {
                continue;
            }
            return Err(format!(
                "edge_proxy.trusted_proxy_cidrs contains invalid ip rule: {raw}"
            ));
        }
        for raw in &self.admin_path_prefixes {
            validate_path_rule(raw, "edge_proxy.admin_path_prefixes")?;
        }
        for raw in &self.upload_path_prefixes {
            validate_path_rule(raw, "edge_proxy.upload_path_prefixes")?;
        }
        for raw in &self.thumb_path_prefixes {
            validate_path_rule(raw, "edge_proxy.thumb_path_prefixes")?;
        }
        for raw in &self.strict_rate_limit_path_prefixes {
            validate_path_rule(raw, "edge_proxy.strict_rate_limit_path_prefixes")?;
        }
        for raw in &self.gone_paths {
            validate_path_rule(raw, "edge_proxy.gone_paths")?;
        }
        if self.tls_listener.enabled {
            if self.tls_listener.bind_address.trim().is_empty() {
                return Err("edge_proxy.tls_listener.bind_address is required".to_string());
            }
            if self.tls_listener.port == 0 {
                return Err("edge_proxy.tls_listener.port must be greater than 0".to_string());
            }
            if self.tls_listener.cert_file.trim().is_empty() {
                return Err("edge_proxy.tls_listener.cert_file is required".to_string());
            }
            if self.tls_listener.key_file.trim().is_empty() {
                return Err("edge_proxy.tls_listener.key_file is required".to_string());
            }
        }
        Ok(())
    }
}

fn default_bind_address() -> String {
    loopback_string()
}

fn default_edge_proxy_port() -> u16 {
    9081
}

fn default_upstream_host() -> String {
    loopback_string()
}

fn default_upstream_port() -> u16 {
    9080
}

fn default_upstream_sni() -> String {
    "irongate".to_string()
}

fn default_request_id_header() -> String {
    "x-request-id".to_string()
}

fn default_tls_listener_config() -> EdgeProxyTlsListenerConfig {
    EdgeProxyTlsListenerConfig {
        enabled: false,
        bind_address: default_tls_bind_address(),
        port: default_tls_port(),
        cert_file: String::new(),
        key_file: String::new(),
    }
}

fn default_tls_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_tls_port() -> u16 {
    443
}

fn loopback_string() -> String {
    Ipv4Addr::LOCALHOST.to_string()
}

fn validate_path_rule(raw: &str, field_name: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field_name} must not contain empty values"));
    }
    if !trimmed.starts_with('/') {
        return Err(format!("{field_name} must start with '/'"));
    }
    Ok(())
}

fn validate_optional_timeout(value: Option<u64>, field_name: &str) -> Result<(), String> {
    if let Some(timeout_ms) = value
        && timeout_ms == 0
    {
        return Err(format!("{field_name} must be greater than 0"));
    }
    Ok(())
}
