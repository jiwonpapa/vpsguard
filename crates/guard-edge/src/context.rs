//! 요청 하나에만 존재하는 bounded edge context입니다.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use guard_core::{BotClass, BotReason, CrawlerProvider, UserAgentFamily};

use crate::rate_limit::RouteClass;
use crate::runtime::UpstreamKind;

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
    pub(crate) response_body_bytes_seen: u64,
    pub(crate) response_status: u16,
    pub(crate) upstream_connection_reused: Option<bool>,
    pub(crate) telemetry_emitted: bool,
    pub(crate) bot_class: BotClass,
    pub(crate) bot_provider: Option<CrawlerProvider>,
    pub(crate) bot_verified: bool,
    pub(crate) bot_reason: BotReason,
    pub(crate) user_agent_family: UserAgentFamily,
    pub(crate) route_class: RouteClass,
    pub(crate) authentication_route: bool,
    pub(crate) normalized_route: String,
    pub(crate) route_cost: u8,
    pub(crate) policy_version: u64,
    pub(crate) upstream_kind: UpstreamKind,
    in_flight_requests: Option<Arc<AtomicU64>>,
    origin_in_flight_requests: Option<Arc<AtomicU64>>,
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
            response_body_bytes_seen: 0,
            response_status: 0,
            upstream_connection_reused: None,
            telemetry_emitted: false,
            bot_class: BotClass::Undeclared,
            bot_provider: None,
            bot_verified: false,
            bot_reason: BotReason::NotDeclared,
            user_agent_family: UserAgentFamily::Missing,
            route_class: RouteClass::General,
            authentication_route: false,
            normalized_route: "/".to_owned(),
            route_cost: 1,
            policy_version: 0,
            upstream_kind: UpstreamKind::Application,
            in_flight_requests: None,
            origin_in_flight_requests: None,
        }
    }

    /// 현재 처리 중 요청 gauge에 연결된 context를 만듭니다.
    pub(crate) fn tracked(in_flight_requests: Arc<AtomicU64>) -> Self {
        in_flight_requests.fetch_add(1, Ordering::Relaxed);
        let mut context = Self::new();
        context.in_flight_requests = Some(in_flight_requests);
        context
    }

    /// 이 요청을 포함한 현재 처리 중 요청 수입니다.
    pub(crate) fn in_flight_requests(&self) -> u64 {
        self.in_flight_requests
            .as_ref()
            .map_or(0, |value| value.load(Ordering::Relaxed))
    }

    /// origin 동시 요청 permit을 원자 획득하고 context 수명에 묶습니다.
    pub(crate) fn try_acquire_origin_capacity(
        &mut self,
        origin_in_flight_requests: Arc<AtomicU64>,
        max_in_flight_requests: u64,
    ) -> bool {
        if self.origin_in_flight_requests.is_some() {
            return true;
        }
        let mut current = origin_in_flight_requests.load(Ordering::Acquire);
        loop {
            if current >= max_in_flight_requests {
                return false;
            }
            match origin_in_flight_requests.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.origin_in_flight_requests = Some(origin_in_flight_requests);
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for RequestContext {
    fn drop(&mut self) {
        if let Some(in_flight_requests) = &self.in_flight_requests {
            in_flight_requests.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(origin_in_flight_requests) = &self.origin_in_flight_requests {
            origin_in_flight_requests.fetch_sub(1, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::RequestContext;

    #[test]
    fn tracked_context_decrements_in_flight_gauge_on_drop() {
        let gauge = Arc::new(AtomicU64::new(0));
        {
            let context = RequestContext::tracked(Arc::clone(&gauge));
            assert_eq!(context.in_flight_requests(), 1);
        }
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn origin_capacity_permit_is_atomic_and_released_on_drop() {
        let origin_in_flight = Arc::new(AtomicU64::new(0));
        let mut first = RequestContext::new();
        let mut second = RequestContext::new();
        let mut rejected = RequestContext::new();

        assert!(first.try_acquire_origin_capacity(Arc::clone(&origin_in_flight), 2));
        assert!(second.try_acquire_origin_capacity(Arc::clone(&origin_in_flight), 2));
        assert!(!rejected.try_acquire_origin_capacity(Arc::clone(&origin_in_flight), 2));
        assert_eq!(origin_in_flight.load(Ordering::Relaxed), 2);

        drop(first);
        assert!(rejected.try_acquire_origin_capacity(Arc::clone(&origin_in_flight), 2));
        assert_eq!(origin_in_flight.load(Ordering::Relaxed), 2);

        drop(second);
        drop(rejected);
        assert_eq!(origin_in_flight.load(Ordering::Relaxed), 0);
    }
}
