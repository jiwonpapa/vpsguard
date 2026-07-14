//! edge datagram을 bounded aggregate로 변환합니다.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use guard_core::DetectionInput;
use serde::{Deserialize, Serialize};

const LATENCY_WINDOW: usize = 2_048;

/// edge telemetry decode 계약입니다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEnvelope {
    /// schema 버전입니다.
    pub schema_version: u32,
    /// request 식별자입니다.
    pub request_id: String,
    /// method입니다.
    pub method: String,
    /// bounded route class입니다.
    pub route_class: String,
    /// query와 identifier가 제거된 route key입니다.
    pub normalized_route: String,
    /// profile 기반 route 비용입니다.
    pub route_cost: u8,
    /// status입니다.
    pub status: u16,
    /// 전체 지연 microseconds입니다.
    pub latency_micros: u64,
    /// 검증된 client IP입니다.
    pub client_ip: Option<IpAddr>,
    /// request body bytes입니다.
    pub request_body_bytes: u64,
    /// response body bytes입니다.
    pub response_body_bytes: u64,
    /// upstream connection 재사용 여부입니다.
    pub upstream_connection_reused: Option<bool>,
    /// edge 판정입니다.
    pub decision: String,
    /// edge에 적용된 정책 버전입니다.
    pub policy_version: u64,
    /// 발생 Unix epoch milliseconds입니다.
    pub occurred_at_unix_ms: u64,
}

/// UI와 API가 읽는 현재 traffic 요약입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSummary {
    /// 수집한 전체 요청입니다.
    pub requests: u64,
    /// 2xx 응답입니다.
    pub status_2xx: u64,
    /// 3xx 응답입니다.
    pub status_3xx: u64,
    /// 4xx 응답입니다.
    pub status_4xx: u64,
    /// 5xx 응답입니다.
    pub status_5xx: u64,
    /// 제한된 요청입니다.
    pub throttled: u64,
    /// 거부된 요청입니다.
    pub denied: u64,
    /// browser 검증을 요구한 요청입니다.
    pub challenged: u64,
    /// request body 누적 bytes입니다.
    pub request_body_bytes: u64,
    /// response body 누적 bytes입니다.
    pub response_body_bytes: u64,
    /// 새 upstream connection 수입니다.
    pub upstream_connections: u64,
    /// 재사용한 upstream connection 수입니다.
    pub upstream_connections_reused: u64,
    /// 최근 window p95 지연 microseconds입니다.
    pub latency_p95_micros: u64,
    /// 추적 중인 unique client입니다.
    pub unique_clients: usize,
    /// aggregate cardinality 초과로 누락한 client입니다.
    pub dropped_clients: u64,
}

/// bounded in-memory traffic aggregate입니다.
#[derive(Debug)]
pub struct TrafficAggregator {
    max_clients: usize,
    requests: u64,
    status_buckets: [u64; 4],
    throttled: u64,
    denied: u64,
    challenged: u64,
    request_body_bytes: u64,
    response_body_bytes: u64,
    upstream_connections: u64,
    upstream_connections_reused: u64,
    latencies: VecDeque<u64>,
    clients: HashMap<IpAddr, u64>,
    dropped_clients: u64,
    window: DetectionWindow,
}

#[derive(Debug, Default)]
struct DetectionWindow {
    requests: u64,
    protective: u64,
    server_errors: u64,
    max_route_cost: u8,
    max_latency_micros: u64,
}

impl TrafficAggregator {
    /// unique client 상한을 고정합니다.
    #[must_use]
    pub fn new(max_clients: usize) -> Self {
        Self {
            max_clients,
            requests: 0,
            status_buckets: [0; 4],
            throttled: 0,
            denied: 0,
            challenged: 0,
            request_body_bytes: 0,
            response_body_bytes: 0,
            upstream_connections: 0,
            upstream_connections_reused: 0,
            latencies: VecDeque::with_capacity(LATENCY_WINDOW),
            clients: HashMap::with_capacity(max_clients.min(10_000)),
            dropped_clients: 0,
            window: DetectionWindow::default(),
        }
    }

    /// 한 datagram을 aggregate에 반영합니다. 미래 schema는 무시합니다.
    pub fn ingest(&mut self, telemetry: &TelemetryEnvelope) {
        if telemetry.schema_version != 1 {
            return;
        }
        self.requests = self.requests.saturating_add(1);
        let bucket = match telemetry.status {
            200..=299 => Some(0),
            300..=399 => Some(1),
            400..=499 => Some(2),
            500..=599 => Some(3),
            _ => None,
        };
        if let Some(value) = bucket.and_then(|index| self.status_buckets.get_mut(index)) {
            *value = value.saturating_add(1);
        }
        match telemetry.decision.as_str() {
            "throttle" => self.throttled = self.throttled.saturating_add(1),
            "deny" => self.denied = self.denied.saturating_add(1),
            "challenge" => self.challenged = self.challenged.saturating_add(1),
            _ => {}
        }
        self.window.requests = self.window.requests.saturating_add(1);
        if matches!(
            telemetry.decision.as_str(),
            "throttle" | "challenge" | "deny"
        ) {
            self.window.protective = self.window.protective.saturating_add(1);
        }
        if telemetry.status >= 500 {
            self.window.server_errors = self.window.server_errors.saturating_add(1);
        }
        self.window.max_route_cost = self.window.max_route_cost.max(telemetry.route_cost);
        self.window.max_latency_micros =
            self.window.max_latency_micros.max(telemetry.latency_micros);
        self.request_body_bytes = self
            .request_body_bytes
            .saturating_add(telemetry.request_body_bytes);
        self.response_body_bytes = self
            .response_body_bytes
            .saturating_add(telemetry.response_body_bytes);
        match telemetry.upstream_connection_reused {
            Some(true) => {
                self.upstream_connections_reused =
                    self.upstream_connections_reused.saturating_add(1);
            }
            Some(false) => {
                self.upstream_connections = self.upstream_connections.saturating_add(1);
            }
            None => {}
        }
        if self.latencies.len() == LATENCY_WINDOW {
            self.latencies.pop_front();
        }
        self.latencies.push_back(telemetry.latency_micros);
        if let Some(client_ip) = telemetry.client_ip {
            if let Some(count) = self.clients.get_mut(&client_ip) {
                *count = count.saturating_add(1);
            } else if self.clients.len() < self.max_clients {
                self.clients.insert(client_ip, 1);
            } else {
                self.dropped_clients = self.dropped_clients.saturating_add(1);
            }
        }
    }

    /// 현재 aggregate snapshot을 생성합니다.
    #[must_use]
    pub fn summary(&self) -> TrafficSummary {
        let mut sorted = self.latencies.iter().copied().collect::<Vec<_>>();
        sorted.sort_unstable();
        let p95_index = sorted
            .len()
            .saturating_mul(95)
            .div_ceil(100)
            .saturating_sub(1);
        TrafficSummary {
            requests: self.requests,
            status_2xx: self.status_buckets[0],
            status_3xx: self.status_buckets[1],
            status_4xx: self.status_buckets[2],
            status_5xx: self.status_buckets[3],
            throttled: self.throttled,
            denied: self.denied,
            challenged: self.challenged,
            request_body_bytes: self.request_body_bytes,
            response_body_bytes: self.response_body_bytes,
            upstream_connections: self.upstream_connections,
            upstream_connections_reused: self.upstream_connections_reused,
            latency_p95_micros: sorted.get(p95_index).copied().unwrap_or_default(),
            unique_clients: self.clients.len(),
            dropped_clients: self.dropped_clients,
        }
    }

    /// 현재 detection window를 입력으로 변환하고 새 window를 시작합니다.
    pub fn take_detection_input(
        &mut self,
        resource_signals_available: bool,
    ) -> Option<DetectionInput> {
        if self.window.requests == 0 {
            return None;
        }
        let window = std::mem::take(&mut self.window);
        let protective_percent = window
            .protective
            .saturating_mul(100)
            .checked_div(window.requests)
            .unwrap_or_default();
        let error_percent = window
            .server_errors
            .saturating_mul(100)
            .checked_div(window.requests)
            .unwrap_or_default();
        let volume_pressure = if window.requests >= 500 {
            80
        } else if window.requests >= 100 {
            50
        } else {
            0
        };
        let latency_pressure = if window.max_latency_micros >= 5_000_000 {
            90
        } else if window.max_latency_micros >= 1_000_000 {
            55
        } else {
            0
        };
        Some(DetectionInput {
            trust: 40,
            automation: u8::try_from(protective_percent.min(100))
                .unwrap_or(100)
                .max(volume_pressure),
            route_cost: window.max_route_cost.saturating_mul(6).min(100),
            upstream_pressure: u8::try_from(error_percent.min(100))
                .unwrap_or(100)
                .max(latency_pressure),
            resource_signals_available,
            session_continuity: false,
            crawler_verified: false,
        })
    }
}

#[cfg(test)]
#[path = "telemetry/tests.rs"]
mod tests;
