use std::net::IpAddr;

use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::runtime_config::EdgeRuntimeConfig;

pub(crate) fn request_header_value(req: &RequestHeader, name: &str) -> Option<String> {
    req.headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn request_target(req: &RequestHeader) -> String {
    req.uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| req.uri.path().to_string())
}

pub(crate) fn content_length(req: &RequestHeader) -> Option<u64> {
    request_header_value(req, "content-length").and_then(|value| value.parse::<u64>().ok())
}

pub(crate) fn direct_client_ip(session: &Session) -> Option<IpAddr> {
    session
        .as_downstream()
        .client_addr()
        .and_then(|addr| addr.as_inet().map(|inet| inet.ip()))
}

pub(crate) fn first_forwarded_for(value: &str) -> Option<String> {
    value
        .split(',')
        .map(str::trim)
        .find(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn effective_client_ip_from_headers(
    forwarded_for: Option<&str>,
    direct_ip: Option<IpAddr>,
    trust_forwarded_headers: bool,
) -> Option<IpAddr> {
    if trust_forwarded_headers {
        forwarded_for
            .and_then(first_forwarded_for)
            .and_then(|value| value.parse::<IpAddr>().ok())
            .or(direct_ip)
    } else {
        direct_ip
    }
}

pub(crate) fn path_matches_rule(path: &str, rule: &str) -> bool {
    if rule == "/" {
        return true;
    }

    path == rule
        || path
            .strip_prefix(rule)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub(crate) fn select_rate_limit(path: &str, config: &EdgeRuntimeConfig) -> Option<u32> {
    if config
        .upload_path_prefixes
        .iter()
        .any(|rule| path_matches_rule(path, rule))
    {
        config
            .upload_rate_limit_requests_per_minute
            .or(config.rate_limit_requests_per_minute)
    } else if config
        .strict_rate_limit_path_prefixes
        .iter()
        .any(|rule| path_matches_rule(path, rule))
    {
        config
            .strict_rate_limit_requests_per_minute
            .or(config.rate_limit_requests_per_minute)
    } else if config
        .thumb_path_prefixes
        .iter()
        .any(|rule| path_matches_rule(path, rule))
    {
        config
            .thumb_rate_limit_requests_per_minute
            .or(config.rate_limit_requests_per_minute)
    } else {
        config.rate_limit_requests_per_minute
    }
}

fn normalize_forwarded_proto(raw: &str) -> Option<String> {
    let normalized = raw
        .split(',')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    match normalized.as_str() {
        "http" | "https" => Some(normalized),
        _ => None,
    }
}

fn downstream_is_tls(session: &Session) -> bool {
    session
        .as_downstream()
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .is_some()
}

pub(crate) fn effective_proto(
    forwarded_proto: Option<&str>,
    downstream_tls: bool,
    trust_forwarded_headers: bool,
) -> String {
    if trust_forwarded_headers
        && let Some(proto) = forwarded_proto.and_then(normalize_forwarded_proto)
    {
        return proto;
    }

    if downstream_tls {
        "https".to_string()
    } else {
        "http".to_string()
    }
}

pub(crate) fn current_proto(session: &Session, trust_forwarded_headers: bool) -> String {
    effective_proto(
        request_header_value(session.req_header(), "x-forwarded-proto").as_deref(),
        downstream_is_tls(session),
        trust_forwarded_headers,
    )
}

pub(crate) fn canonical_redirect_location(
    proto: &str,
    canonical_host: &str,
    target: &str,
) -> String {
    format!("{proto}://{canonical_host}{target}")
}

#[cfg(test)]
#[path = "request_policy/tests.rs"]
mod tests;
