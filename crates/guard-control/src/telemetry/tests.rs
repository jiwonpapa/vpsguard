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
        ..TelemetryEnvelope::default()
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

#[test]
fn bounds_and_aggregates_one_second_live_ring() {
    let mut aggregate = TrafficAggregator::with_live_window(10, 2);
    let mut first = telemetry(1, 200, 100);
    first.occurred_at_unix_ms = 1_100;
    let mut same_second = telemetry(2, 503, 300);
    same_second.occurred_at_unix_ms = 1_900;
    same_second.decision = "throttle".to_owned();
    let mut second = telemetry(3, 200, 200);
    second.occurred_at_unix_ms = 2_000;
    let mut third = telemetry(4, 200, 400);
    third.occurred_at_unix_ms = 3_000;

    aggregate.ingest(&first);
    aggregate.ingest(&same_second);
    aggregate.ingest(&second);
    aggregate.ingest(&third);

    let series = aggregate.live_series(0);
    assert_eq!(series.len(), 2);
    assert_eq!(series[0].bucket_unix_ms, 2_000);
    assert_eq!(series[1].bucket_unix_ms, 3_000);

    let mut current = TrafficAggregator::with_live_window(10, 2);
    current.ingest(&first);
    current.ingest(&same_second);
    let point = &current.live_series(0)[0];
    assert_eq!(point.requests, 2);
    assert_eq!(point.errors, 1);
    assert_eq!(point.throttled, 1);
    assert_eq!(point.latency_avg_micros, 200);
}

#[test]
fn summary_expires_old_traffic_and_reports_bot_delivery_health() {
    let mut aggregate = TrafficAggregator::with_live_window(10, 10);
    let mut old = telemetry(1, 200, 100);
    old.occurred_at_unix_ms = 1_000;
    aggregate.ingest(&old);

    let mut current = telemetry(2, 403, 300);
    current.occurred_at_unix_ms = 20_000;
    current.decision = "deny".to_owned();
    current.bot_class = guard_core::BotClass::UnapprovedDeclaredBot;
    current.in_flight_requests = 3;
    current.edge_telemetry_emitted = 41;
    current.edge_telemetry_dropped = 2;
    current.edge_telemetry_reconnected = 1;
    aggregate.ingest(&current);

    let summary = aggregate.summary_at(20_500);
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.status_2xx, 0);
    assert_eq!(summary.status_4xx, 1);
    assert_eq!(summary.bot_requests, 1);
    assert_eq!(summary.bot_denied, 1);
    assert_eq!(summary.in_flight_requests, 3);
    assert_eq!(summary.edge_telemetry_dropped, 2);
    assert_eq!(summary.requests_per_second_milli, 100);
}
