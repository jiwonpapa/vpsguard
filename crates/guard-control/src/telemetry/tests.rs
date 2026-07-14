//! telemetry aggregate 회귀 테스트입니다.

use std::net::{IpAddr, Ipv4Addr};

use super::{TelemetryEnvelope, TrafficAggregator};

fn telemetry(ip: u8, status: u16, latency: u64) -> TelemetryEnvelope {
    TelemetryEnvelope {
        schema_version: 1,
        request_id: format!("request-{ip}"),
        method: "GET".to_owned(),
        route_class: "general".to_owned(),
        status,
        latency_micros: latency,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, ip))),
        request_body_bytes: 0,
        decision: "allow".to_owned(),
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
