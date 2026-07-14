//! 요청 하나에만 존재하는 bounded edge context입니다.

use std::net::IpAddr;
use std::time::Instant;

use crate::rate_limit::RouteClass;

/// Pingora request lifecycle에서 공유하는 최소 context입니다.
#[derive(Debug)]
pub(crate) struct RequestContext {
    pub(crate) request_id: String,
    pub(crate) started_at: Instant,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) host: Option<String>,
    pub(crate) direct_peer: Option<IpAddr>,
    pub(crate) client_ip: Option<IpAddr>,
    pub(crate) forwarded_headers_trusted: bool,
    pub(crate) request_body_bytes_seen: u64,
    pub(crate) route_class: RouteClass,
    pub(crate) normalized_route: String,
    pub(crate) route_cost: u8,
    pub(crate) policy_version: u64,
}

impl RequestContext {
    pub(crate) fn new() -> Self {
        Self {
            request_id: String::new(),
            started_at: Instant::now(),
            method: String::new(),
            path: String::new(),
            host: None,
            direct_peer: None,
            client_ip: None,
            forwarded_headers_trusted: false,
            request_body_bytes_seen: 0,
            route_class: RouteClass::General,
            normalized_route: "/".to_owned(),
            route_cost: 1,
            policy_version: 0,
        }
    }
}
