//! Host, path, forwarded chain과 요청 한도에 대한 순수 정책 함수입니다.

use std::net::IpAddr;

use ipnet::IpNet;

/// Host header에서 port와 대소문자 차이를 제거합니다.
#[must_use]
pub fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(without_bracket) = trimmed.strip_prefix('[')
        && let Some((host, _)) = without_bracket.split_once(']')
    {
        return host.to_owned();
    }
    trimmed
        .split_once(':')
        .map_or(trimmed.as_str(), |(host, _)| host)
        .to_owned()
}

/// Host가 exact 또는 `*.` wildcard 규칙과 일치하는지 확인합니다.
#[must_use]
pub fn host_matches_rule(host: &str, rule: &str) -> bool {
    let host = normalize_host(host);
    let rule = normalize_host(rule);
    if let Some(suffix) = rule.strip_prefix("*.") {
        return host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    }
    host == rule
}

/// 요청 Host가 allowlist에 포함되는지 확인합니다.
#[must_use]
pub fn host_allowed(host: Option<&str>, allowed_hosts: &[String]) -> bool {
    host.is_some_and(|candidate| {
        allowed_hosts
            .iter()
            .any(|rule| host_matches_rule(candidate, rule))
    })
}

/// 요청 경로가 exact 또는 segment prefix 규칙과 일치하는지 확인합니다.
#[must_use]
pub fn path_matches_rule(path: &str, rule: &str) -> bool {
    rule == "/"
        || path == rule
        || path
            .strip_prefix(rule)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// 경로가 등록된 prefix 중 하나에 포함되는지 확인합니다.
#[must_use]
pub fn path_matches_any(path: &str, rules: &[String]) -> bool {
    rules.iter().any(|rule| path_matches_rule(path, rule))
}

/// direct peer와 검증된 forwarded chain에서 실제 client IP를 계산합니다.
///
/// direct peer가 trusted proxy가 아니거나 header가 손상되면 direct peer를 사용합니다.
/// trusted chain은 오른쪽부터 제거하고 처음 만나는 untrusted 주소를 client로 선택합니다.
#[must_use]
pub fn effective_client_ip(
    direct_peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    if !ip_is_trusted(direct_peer, trusted_proxies) {
        return direct_peer;
    }
    let Some(raw_chain) = forwarded_for else {
        return direct_peer;
    };
    let parsed = raw_chain
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(chain) = parsed else {
        return direct_peer;
    };
    if chain.is_empty() {
        return direct_peer;
    }
    chain
        .iter()
        .rev()
        .copied()
        .find(|candidate| !ip_is_trusted(*candidate, trusted_proxies))
        .unwrap_or(chain[0])
}

/// 주소가 trusted proxy CIDR에 포함되는지 확인합니다.
#[must_use]
pub fn ip_is_trusted(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies.iter().any(|network| network.contains(&ip))
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
