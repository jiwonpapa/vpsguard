//! edge datagram을 bounded aggregate로 변환합니다.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use guard_core::{
    BotClass, BotReason, CrawlerProvider, DetectionInput, HostPressure, UserAgentFamily,
};
use serde::{Deserialize, Serialize};

const LATENCY_WINDOW: usize = 2_048;
const DEFAULT_LIVE_SECONDS: usize = 900;

/// 1초·10초·1분 traffic 시계열 bucket입니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SeriesPoint {
    pub(crate) bucket_unix_ms: u64,
    pub(crate) requests: u64,
    pub(crate) errors: u64,
    pub(crate) throttled: u64,
    pub(crate) latency_avg_micros: u64,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
}

/// edge telemetry decode 계약입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
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
    /// 선언형 bot의 bounded 분류입니다.
    #[serde(default)]
    pub bot_class: BotClass,
    /// 검증 대상 crawler provider입니다.
    #[serde(default)]
    pub bot_provider: Option<CrawlerProvider>,
    /// 공식 source identity 검증 여부입니다.
    #[serde(default)]
    pub bot_verified: bool,
    /// bot 판정의 안정 reason code입니다.
    #[serde(default)]
    pub bot_reason: BotReason,
    /// 원문을 보존하지 않는 User-Agent family입니다.
    #[serde(default)]
    pub user_agent_family: UserAgentFamily,
    /// event 시점의 처리 중 요청 수입니다.
    #[serde(default)]
    pub in_flight_requests: u64,
    /// edge telemetry 전송 성공 수입니다.
    #[serde(default)]
    pub edge_telemetry_emitted: u64,
    /// edge telemetry 손실 수입니다.
    #[serde(default)]
    pub edge_telemetry_dropped: u64,
    /// edge telemetry receiver 재연결 수입니다.
    #[serde(default)]
    pub edge_telemetry_reconnected: u64,
    /// 발생 Unix epoch milliseconds입니다.
    pub occurred_at_unix_ms: u64,
}

/// UI와 API가 읽는 현재 traffic 요약입니다.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSummary {
    /// 현재 요약 시간창 크기입니다.
    pub window_seconds: u64,
    /// 현재 요약 시간창 시작입니다.
    pub window_started_at_unix_ms: u64,
    /// 현재 요약 시간창 종료입니다.
    pub window_ended_at_unix_ms: u64,
    /// 최근 10초 평균 RPS에 1,000을 곱한 정수입니다.
    pub requests_per_second_milli: u64,
    /// 현재 시간창에서 수집한 요청입니다.
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
    /// event 시점에 edge가 처리 중이던 요청 수입니다.
    pub in_flight_requests: u64,
    /// 현재 시간창의 선언형 bot 요청입니다.
    pub bot_requests: u64,
    /// 현재 시간창의 선언형 bot 거부입니다.
    pub bot_denied: u64,
    /// edge telemetry 전송 성공 누계입니다.
    pub edge_telemetry_emitted: u64,
    /// edge telemetry 손실 누계입니다.
    pub edge_telemetry_dropped: u64,
    /// edge telemetry 재연결 누계입니다.
    pub edge_telemetry_reconnected: u64,
}

/// bounded in-memory traffic aggregate입니다.
#[derive(Debug)]
pub struct TrafficAggregator {
    max_clients: usize,
    latencies: VecDeque<(u64, u64)>,
    clients: HashMap<IpAddr, u64>,
    window: DetectionWindow,
    live_seconds: usize,
    live_buckets: VecDeque<LiveSecondBucket>,
}

#[derive(Debug, Default)]
struct DetectionWindow {
    requests: u64,
    protective: u64,
    server_errors: u64,
    verified_crawler_requests: u64,
    max_route_cost: u8,
    max_latency_micros: u64,
}

#[derive(Debug, Default)]
struct LiveSecondBucket {
    bucket_unix_ms: u64,
    requests: u64,
    errors: u64,
    throttled: u64,
    latency_sum_micros: u64,
    request_body_bytes: u64,
    response_body_bytes: u64,
    status_buckets: [u64; 4],
    denied: u64,
    challenged: u64,
    upstream_connections: u64,
    upstream_connections_reused: u64,
    dropped_clients: u64,
    bot_requests: u64,
    bot_denied: u64,
    in_flight_requests: u64,
    edge_telemetry_emitted: u64,
    edge_telemetry_dropped: u64,
    edge_telemetry_reconnected: u64,
}

impl LiveSecondBucket {
    fn ingest(&mut self, telemetry: &TelemetryEnvelope) {
        self.requests = self.requests.saturating_add(1);
        self.errors = self
            .errors
            .saturating_add(u64::from(telemetry.status >= 500));
        self.throttled = self
            .throttled
            .saturating_add(u64::from(telemetry.decision == "throttle"));
        self.latency_sum_micros = self
            .latency_sum_micros
            .saturating_add(telemetry.latency_micros);
        self.request_body_bytes = self
            .request_body_bytes
            .saturating_add(telemetry.request_body_bytes);
        self.response_body_bytes = self
            .response_body_bytes
            .saturating_add(telemetry.response_body_bytes);
        let status_index = match telemetry.status {
            200..=299 => Some(0),
            300..=399 => Some(1),
            400..=499 => Some(2),
            500..=599 => Some(3),
            _ => None,
        };
        if let Some(value) = status_index.and_then(|index| self.status_buckets.get_mut(index)) {
            *value = value.saturating_add(1);
        }
        self.denied = self
            .denied
            .saturating_add(u64::from(telemetry.decision == "deny"));
        self.challenged = self
            .challenged
            .saturating_add(u64::from(telemetry.decision == "challenge"));
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
        let declared_bot = telemetry.bot_class != BotClass::Undeclared;
        self.bot_requests = self.bot_requests.saturating_add(u64::from(declared_bot));
        self.bot_denied = self
            .bot_denied
            .saturating_add(u64::from(declared_bot && telemetry.decision == "deny"));
        self.in_flight_requests = telemetry.in_flight_requests;
        self.edge_telemetry_emitted = telemetry.edge_telemetry_emitted;
        self.edge_telemetry_dropped = telemetry.edge_telemetry_dropped;
        self.edge_telemetry_reconnected = telemetry.edge_telemetry_reconnected;
    }

    fn point(&self) -> SeriesPoint {
        SeriesPoint {
            bucket_unix_ms: self.bucket_unix_ms,
            requests: self.requests,
            errors: self.errors,
            throttled: self.throttled,
            latency_avg_micros: self
                .latency_sum_micros
                .checked_div(self.requests)
                .unwrap_or_default(),
            request_body_bytes: self.request_body_bytes,
            response_body_bytes: self.response_body_bytes,
        }
    }
}

impl TrafficAggregator {
    /// unique client 상한을 고정합니다.
    #[must_use]
    pub fn new(max_clients: usize) -> Self {
        Self::with_live_window(max_clients, DEFAULT_LIVE_SECONDS)
    }

    /// unique client와 1초 live ring의 상한을 고정합니다.
    #[must_use]
    pub fn with_live_window(max_clients: usize, live_seconds: usize) -> Self {
        Self {
            max_clients,
            latencies: VecDeque::with_capacity(LATENCY_WINDOW),
            clients: HashMap::with_capacity(max_clients.min(10_000)),
            window: DetectionWindow::default(),
            live_seconds,
            live_buckets: VecDeque::with_capacity(live_seconds),
        }
    }

    /// 한 datagram을 aggregate에 반영합니다. 미래 schema는 무시합니다.
    pub fn ingest(&mut self, telemetry: &TelemetryEnvelope) {
        if telemetry.schema_version != 1 {
            return;
        }
        self.ingest_live(telemetry);
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
        self.window.verified_crawler_requests = self
            .window
            .verified_crawler_requests
            .saturating_add(u64::from(telemetry.bot_verified));
        self.window.max_route_cost = self.window.max_route_cost.max(telemetry.route_cost);
        self.window.max_latency_micros =
            self.window.max_latency_micros.max(telemetry.latency_micros);
        if self.latencies.len() == LATENCY_WINDOW {
            self.latencies.pop_front();
        }
        self.latencies
            .push_back((telemetry.occurred_at_unix_ms, telemetry.latency_micros));
        if let Some(client_ip) = telemetry.client_ip {
            if let Some(last_seen) = self.clients.get_mut(&client_ip) {
                *last_seen = telemetry.occurred_at_unix_ms;
            } else {
                if self.clients.len() >= self.max_clients {
                    let cutoff = telemetry.occurred_at_unix_ms.saturating_sub(
                        u64::try_from(self.live_seconds)
                            .unwrap_or(u64::MAX)
                            .saturating_mul(1_000),
                    );
                    self.clients.retain(|_, last_seen| *last_seen >= cutoff);
                }
                if self.clients.len() < self.max_clients {
                    self.clients
                        .insert(client_ip, telemetry.occurred_at_unix_ms);
                } else if let Some(bucket) = self.live_buckets.back_mut() {
                    bucket.dropped_clients = bucket.dropped_clients.saturating_add(1);
                }
            }
        }
    }

    /// 현재 aggregate snapshot을 생성합니다.
    #[must_use]
    pub fn summary(&self) -> TrafficSummary {
        let now_unix_ms = self
            .live_buckets
            .back()
            .map_or(0, |bucket| bucket.bucket_unix_ms.saturating_add(1_000));
        self.summary_at(now_unix_ms)
    }

    /// 지정 시각 기준 bounded live window snapshot을 생성합니다.
    #[must_use]
    pub fn summary_at(&self, now_unix_ms: u64) -> TrafficSummary {
        let window_seconds = u64::try_from(self.live_seconds).unwrap_or(u64::MAX);
        let window_started_at_unix_ms =
            now_unix_ms.saturating_sub(window_seconds.saturating_mul(1_000));
        let buckets = self
            .live_buckets
            .iter()
            .filter(|bucket| bucket.bucket_unix_ms >= window_started_at_unix_ms)
            .collect::<Vec<_>>();
        let requests = buckets
            .iter()
            .fold(0_u64, |total, bucket| total.saturating_add(bucket.requests));
        let status: [u64; 4] = std::array::from_fn(|index| {
            buckets.iter().fold(0_u64, |total, bucket| {
                total.saturating_add(bucket.status_buckets[index])
            })
        });
        let sum = |value: fn(&LiveSecondBucket) -> u64| {
            buckets
                .iter()
                .fold(0_u64, |total, bucket| total.saturating_add(value(bucket)))
        };
        let mut sorted = self
            .latencies
            .iter()
            .filter(|(occurred_at, _)| *occurred_at >= window_started_at_unix_ms)
            .map(|(_, latency)| *latency)
            .collect::<Vec<_>>();
        sorted.sort_unstable();
        let p95_index = sorted
            .len()
            .saturating_mul(95)
            .div_ceil(100)
            .saturating_sub(1);
        TrafficSummary {
            window_seconds,
            window_started_at_unix_ms,
            window_ended_at_unix_ms: now_unix_ms,
            requests_per_second_milli: buckets
                .iter()
                .filter(|bucket| bucket.bucket_unix_ms >= now_unix_ms.saturating_sub(10_000))
                .fold(0_u64, |total, bucket| total.saturating_add(bucket.requests))
                .saturating_mul(100),
            requests,
            status_2xx: status[0],
            status_3xx: status[1],
            status_4xx: status[2],
            status_5xx: status[3],
            throttled: sum(|bucket| bucket.throttled),
            denied: sum(|bucket| bucket.denied),
            challenged: sum(|bucket| bucket.challenged),
            request_body_bytes: sum(|bucket| bucket.request_body_bytes),
            response_body_bytes: sum(|bucket| bucket.response_body_bytes),
            upstream_connections: sum(|bucket| bucket.upstream_connections),
            upstream_connections_reused: sum(|bucket| bucket.upstream_connections_reused),
            latency_p95_micros: sorted.get(p95_index).copied().unwrap_or_default(),
            unique_clients: self
                .clients
                .values()
                .filter(|last_seen| **last_seen >= window_started_at_unix_ms)
                .count(),
            dropped_clients: sum(|bucket| bucket.dropped_clients),
            in_flight_requests: buckets.last().map_or(0, |bucket| bucket.in_flight_requests),
            bot_requests: sum(|bucket| bucket.bot_requests),
            bot_denied: sum(|bucket| bucket.bot_denied),
            edge_telemetry_emitted: buckets
                .last()
                .map_or(0, |bucket| bucket.edge_telemetry_emitted),
            edge_telemetry_dropped: buckets
                .last()
                .map_or(0, |bucket| bucket.edge_telemetry_dropped),
            edge_telemetry_reconnected: buckets
                .last()
                .map_or(0, |bucket| bucket.edge_telemetry_reconnected),
        }
    }

    /// 지정 시각 이후 bounded 1초 live bucket을 반환합니다.
    pub(crate) fn live_series(&self, since_unix_ms: u64) -> Vec<SeriesPoint> {
        self.live_buckets
            .iter()
            .filter(|bucket| bucket.bucket_unix_ms >= since_unix_ms)
            .map(LiveSecondBucket::point)
            .collect()
    }

    /// 현재 detection window를 입력으로 변환하고 새 window를 시작합니다.
    pub fn take_detection_input(&mut self, host_pressure: HostPressure) -> Option<DetectionInput> {
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
        let crawler_verified =
            window.verified_crawler_requests.saturating_mul(2) >= window.requests;
        Some(DetectionInput {
            trust: if crawler_verified { 75 } else { 40 },
            automation: u8::try_from(protective_percent.min(100))
                .unwrap_or(100)
                .max(volume_pressure),
            route_cost: window.max_route_cost.saturating_mul(6).min(100),
            upstream_pressure: u8::try_from(error_percent.min(100))
                .unwrap_or(100)
                .max(latency_pressure),
            host_pressure,
            session_continuity: false,
            crawler_verified,
        })
    }

    fn ingest_live(&mut self, telemetry: &TelemetryEnvelope) {
        if self.live_seconds == 0 {
            return;
        }
        let bucket_unix_ms = telemetry
            .occurred_at_unix_ms
            .saturating_sub(telemetry.occurred_at_unix_ms % 1_000);
        if let Some(bucket) = self
            .live_buckets
            .iter_mut()
            .rev()
            .find(|bucket| bucket.bucket_unix_ms == bucket_unix_ms)
        {
            bucket.ingest(telemetry);
            return;
        }
        if self
            .live_buckets
            .back()
            .is_some_and(|bucket| bucket.bucket_unix_ms > bucket_unix_ms)
        {
            return;
        }
        let mut bucket = LiveSecondBucket {
            bucket_unix_ms,
            ..LiveSecondBucket::default()
        };
        bucket.ingest(telemetry);
        self.live_buckets.push_back(bucket);
        while self.live_buckets.len() > self.live_seconds {
            self.live_buckets.pop_front();
        }
    }
}

#[cfg(test)]
#[path = "telemetry/tests.rs"]
mod tests;
