"""EDGE-011/OBS-001 integration evidence assertions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def assert_edge_log_privacy(path: Path) -> None:
    """Require sampled rejection events to omit raw path and client IP fields."""
    rejection_events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            fields = json.loads(line).get("fields", {})
        except json.JSONDecodeError:
            continue
        if fields.get("event_code") not in {
            "EDGE_HOST_REJECTED",
            "EDGE_REQUEST_RATE_LIMITED",
        }:
            continue
        rejection_events.append(fields)
        assert "path" not in fields, "raw path leaked into rejection event"
        assert "client_ip" not in fields, "raw client IP leaked into rejection event"
        assert "normalized_route" in fields, "bounded route is missing"
        assert "client_network" in fields, "masked client network is missing"
    assert any(
        event["event_code"] == "EDGE_HOST_REJECTED" for event in rejection_events
    ), "host rejection event was not captured"


def assert_traffic_api(
    traffic_path: Path,
    clients_path: Path,
    routes_path: Path,
    bots_path: Path,
) -> None:
    """Validate bounded live, persistent, and bot telemetry API evidence."""
    traffic = json.loads(traffic_path.read_text(encoding="utf-8"))
    clients = json.loads(clients_path.read_text(encoding="utf-8"))["items"]
    routes = json.loads(routes_path.read_text(encoding="utf-8"))["items"]
    bots = json.loads(bots_path.read_text(encoding="utf-8"))["items"]
    assert traffic["requests"] >= 5
    assert traffic["response_body_bytes"] > 0
    assert traffic["upstream_connections"] >= 1
    assert traffic["window_seconds"] > 0
    assert traffic["requests_per_second_milli"] >= 0
    assert traffic["edge_telemetry_emitted"] >= 1
    assert clients and clients[0]["client_ip"] == "127.0.0.1"
    assert any(route["response_body_bytes"] > 0 for route in routes)
    assert isinstance(bots, list)


def main(argv: list[str] | None = None) -> int:
    """Parse evidence paths and run all integration assertions."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--edge-log", type=Path, required=True)
    parser.add_argument("--traffic", type=Path, required=True)
    parser.add_argument("--clients", type=Path, required=True)
    parser.add_argument("--routes", type=Path, required=True)
    parser.add_argument("--bots", type=Path, required=True)
    arguments = parser.parse_args(argv)
    assert_edge_log_privacy(arguments.edge_log)
    assert_traffic_api(
        arguments.traffic,
        arguments.clients,
        arguments.routes,
        arguments.bots,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
