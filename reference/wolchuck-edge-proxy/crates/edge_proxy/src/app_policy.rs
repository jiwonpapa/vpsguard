use std::net::IpAddr;

use common::network::is_ip_allowed;

use crate::EdgeProxyApp;
use crate::request_policy::path_matches_rule;
use crate::runtime_config::normalize_host;

fn host_matches_rule(host: &str, rule: &str) -> bool {
    if rule.is_empty() {
        return false;
    }

    if host == rule {
        return true;
    }

    let suffix = if let Some(value) = rule.strip_prefix("*.") {
        value
    } else if let Some(value) = rule.strip_prefix('.') {
        value
    } else {
        return false;
    };

    !suffix.is_empty()
        && host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

impl EdgeProxyApp {
    pub(crate) fn host_allowed(&self, host: Option<&str>) -> bool {
        let Some(raw_host) = host else {
            return self.config.allowed_hosts.is_empty()
                && self.config.passthrough_hosts.is_empty();
        };

        let normalized = normalize_host(raw_host);
        if let Some(canonical_host) = self.config.canonical_host.as_deref()
            && normalized == canonical_host
        {
            return true;
        }

        if self
            .config
            .passthrough_hosts
            .iter()
            .any(|item| host_matches_rule(&normalized, item))
        {
            return true;
        }

        if self.config.allowed_hosts.is_empty() {
            return true;
        }

        self.config
            .allowed_hosts
            .iter()
            .any(|item| host_matches_rule(&normalized, item))
    }

    pub(crate) fn host_passthrough(&self, host: Option<&str>) -> bool {
        let Some(raw_host) = host else {
            return false;
        };

        let normalized = normalize_host(raw_host);
        self.config
            .passthrough_hosts
            .iter()
            .any(|item| host_matches_rule(&normalized, item))
    }

    pub(crate) fn admin_ip_allowed(&self, ip: Option<IpAddr>) -> bool {
        if self.config.admin_allowed_rules.is_empty() {
            return true;
        }

        ip.is_some_and(|candidate| is_ip_allowed(candidate, &self.config.admin_allowed_rules))
    }

    pub(crate) fn blocked_ip_denied(&self, ip: Option<IpAddr>) -> bool {
        ip.is_some_and(|candidate| is_ip_allowed(candidate, &self.config.blocked_rules))
    }

    pub(crate) fn forwarded_headers_trusted(&self, direct_ip: Option<IpAddr>) -> bool {
        if self.config.trusted_proxy_rules.is_empty() {
            return false;
        }

        direct_ip
            .is_some_and(|candidate| is_ip_allowed(candidate, &self.config.trusted_proxy_rules))
    }

    pub(crate) fn is_admin_path(&self, path: &str) -> bool {
        self.config
            .admin_path_prefixes
            .iter()
            .any(|rule| path_matches_rule(path, rule))
    }

    pub(crate) fn is_upload_path(&self, path: &str) -> bool {
        self.config
            .upload_path_prefixes
            .iter()
            .any(|rule| path_matches_rule(path, rule))
    }

    #[allow(dead_code)]
    pub(crate) fn is_thumb_path(&self, path: &str) -> bool {
        self.config
            .thumb_path_prefixes
            .iter()
            .any(|rule| path_matches_rule(path, rule))
    }

    #[allow(dead_code)]
    pub(crate) fn is_strict_rate_limit_path(&self, path: &str) -> bool {
        self.config
            .strict_rate_limit_path_prefixes
            .iter()
            .any(|rule| path_matches_rule(path, rule))
    }

    pub(crate) fn is_gone_path(&self, path: &str) -> bool {
        self.config
            .gone_paths
            .iter()
            .any(|rule| path_matches_rule(path, rule))
    }
}

#[cfg(test)]
#[path = "app_policy/tests.rs"]
mod tests;
