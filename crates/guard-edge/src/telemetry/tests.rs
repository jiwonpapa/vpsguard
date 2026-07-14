//! telemetry privacy와 backpressure 회귀 테스트입니다.

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::net::UnixDatagram;

use super::{DecisionKind, RequestTelemetry, TelemetrySink};
use crate::rate_limit::RouteClass;

fn fixture() -> RequestTelemetry {
    RequestTelemetry {
        schema_version: 1,
        request_id: "guard-1".to_owned(),
        method: "GET".to_owned(),
        route_class: RouteClass::Strict,
        normalized_route: "/bbs/board.php".to_owned(),
        route_cost: 4,
        status: 200,
        latency_micros: 500,
        client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        request_body_bytes: 0,
        response_body_bytes: 512,
        upstream_connection_reused: Some(true),
        decision: DecisionKind::Allow,
        policy_version: 3,
        occurred_at_unix_ms: 1_000,
    }
}

#[test]
fn emits_bounded_privacy_safe_datagram() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = UnixDatagram::pair()?;
    receiver.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    let sink = TelemetrySink::from_socket(sender);
    sink.emit(&fixture());
    let mut buffer = [0_u8; 4_096];
    let length = receiver.recv(&mut buffer)?;
    let decoded: RequestTelemetry = serde_json::from_slice(&buffer[..length])?;
    assert_eq!(decoded, fixture());
    assert_eq!(sink.emitted(), 1);
    assert_eq!(sink.dropped(), 0);
    Ok(())
}

#[test]
fn disconnected_sink_only_increments_drop_counter() {
    let sink = TelemetrySink::connect(std::path::Path::new("/run/vps-guard/nonexistent-test.sock"));
    sink.emit(&fixture());
    assert_eq!(sink.dropped(), 1);
}
