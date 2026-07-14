//! edge datagram을 bounded aggregate로 변환합니다.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

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
    /// status입니다.
    pub status: u16,
    /// 전체 지연 microseconds입니다.
    pub latency_micros: u64,
    /// 검증된 client IP입니다.
    pub client_ip: Option<IpAddr>,
    /// request body bytes입니다.
    pub request_body_bytes: u64,
    /// edge 판정입니다.
    pub decision: String,
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
    latencies: VecDeque<u64>,
    clients: HashMap<IpAddr, u64>,
    dropped_clients: u64,
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
            latencies: VecDeque::with_capacity(LATENCY_WINDOW),
            clients: HashMap::with_capacity(max_clients.min(10_000)),
            dropped_clients: 0,
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
            _ => {}
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
            latency_p95_micros: sorted.get(p95_index).copied().unwrap_or_default(),
            unique_clients: self.clients.len(),
            dropped_clients: self.dropped_clients,
        }
    }
}

#[cfg(test)]
#[path = "telemetry/tests.rs"]
mod tests;
