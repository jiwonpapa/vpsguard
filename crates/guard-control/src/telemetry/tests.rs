//! telemetry aggregate 회귀 테스트입니다.

use std::net::{IpAddr, Ipv4Addr};

use super::{TelemetryEnvelope, TrafficAggregator};

fn telemetry(ip: u8, status: u16, latency: u64) -> TelemetryEnvelope {
    TelemetryEnvelope {
        schema_version: 1,
        request_id: format!("request-{ip}"),
        method: "GET".to_owned(),
        route_class: "general".to_owned(),
        normalized_route: "/bbs/board.php".to_owned(),
        route_cost: 4,
        status,
        latency_micros: latency,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, ip))),
        request_body_bytes: 0,
        response_body_bytes: 128,
        upstream_connection_reused: Some(false),
        decision: "allow".to_owned(),
        policy_version: 0,
        occurred_at_unix_ms: 1_000,
    }
}

#[test]
fn aggregates_status_latency_and_clients() {
    let mut aggregate = TrafficAggregator::new(10);
    aggregate.ingest(&telemetry(1, 200, 100));
    aggregate.ingest(&telemetry(2, 404, 900));
    let summary = aggregate.summary();
    assert_eq!(summary.requests, 2);
    assert_eq!(summary.status_2xx, 1);
    assert_eq!(summary.status_4xx, 1);
    assert_eq!(summary.latency_p95_micros, 900);
    assert_eq!(summary.unique_clients, 2);
}

#[test]
fn bounds_client_cardinality() {
    let mut aggregate = TrafficAggregator::new(1);
    aggregate.ingest(&telemetry(1, 200, 100));
    aggregate.ingest(&telemetry(2, 200, 100));
    let summary = aggregate.summary();
    assert_eq!(summary.unique_clients, 1);
    assert_eq!(summary.dropped_clients, 1);
}

#[test]
fn creates_and_resets_detection_window() {
    let mut aggregate = TrafficAggregator::new(10);
    let mut sample = telemetry(1, 503, 6_000_000);
    sample.route_cost = 15;
    sample.decision = "throttle".to_owned();
    aggregate.ingest(&sample);
    let input = aggregate.take_detection_input(true);
    assert!(input.is_some_and(|value| {
        value.automation == 100 && value.route_cost == 90 && value.upstream_pressure == 100
    }));
    assert!(aggregate.take_detection_input(true).is_none());
}
