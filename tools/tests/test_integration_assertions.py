"""EDGE-011/OBS-001 integration assertion regression tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.integration_assertions import (
    assert_edge_log_privacy,
    assert_traffic_api,
)


class IntegrationAssertionTests(unittest.TestCase):
    """Keep privacy and telemetry evidence checks fail closed."""

    def test_edge_rejection_requires_masked_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "edge.log"
            fields = {
                "event_code": "EDGE_HOST_REJECTED",
                "normalized_route": "/:opaque",
                "client_network": "203.0.113.0/24",
            }
            log.write_text(json.dumps({"fields": fields}), encoding="utf-8")
            assert_edge_log_privacy(log)
            fields["client_ip"] = "203.0.113.7"
            log.write_text(json.dumps({"fields": fields}), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "raw client IP"):
                assert_edge_log_privacy(log)

    def test_traffic_api_requires_live_and_persistent_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "traffic.json": {
                    "requests": 5,
                    "response_body_bytes": 128,
                    "upstream_connections": 1,
                    "window_seconds": 900,
                    "requests_per_second_milli": 100,
                    "edge_telemetry_emitted": 5,
                },
                "clients.json": {"items": [{"client_ip": "127.0.0.1"}]},
                "routes.json": {"items": [{"response_body_bytes": 128}]},
                "bots.json": {"items": []},
            }
            for name, value in fixtures.items():
                (root / name).write_text(json.dumps(value), encoding="utf-8")
            assert_traffic_api(
                root / "traffic.json",
                root / "clients.json",
                root / "routes.json",
                root / "bots.json",
            )
