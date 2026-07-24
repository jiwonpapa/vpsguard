"""NFR-001 load summary and fixed budget regression tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.errors import HarnessError
from tools.vpsguard_harness.load_regression import LoadMetrics, evaluate, load_metrics


class LoadRegressionTests(unittest.TestCase):
    """Direct/guard evidence is strict, numeric and budgeted."""

    def test_parses_k6_summary_and_accepts_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "metrics": {
                            "http_req_duration": {"p(95)": 12.5},
                            "http_reqs": {"count": 15_000, "rate": 1_000},
                            "http_req_failed": {"value": 0},
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                load_metrics(summary),
                LoadMetrics(p95_ms=12.5, requests_per_second=1_000.0, failed_rate=0.0),
            )
        result = evaluate(
            LoadMetrics(12.0, 1_000.0, 0.0),
            LoadMetrics(13.5, 920.0, 0.0),
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.p95_overhead_ms, 1.5)
        self.assertEqual(result.throughput_reduction_percent, 8.0)

    def test_rejects_latency_throughput_failure_and_invalid_baseline(self) -> None:
        self.assertFalse(
            evaluate(
                LoadMetrics(10.0, 1_000.0, 0.0),
                LoadMetrics(12.1, 899.0, 0.0),
            ).passed
        )
        with self.assertRaises(HarnessError):
            evaluate(
                LoadMetrics(10.0, 0.0, 0.0),
                LoadMetrics(10.0, 1.0, 0.0),
            )

    def test_rejects_invalid_or_non_finite_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "metrics": {
                            "http_req_duration": {"p(95)": float("nan")},
                            "http_reqs": {"rate": 1_000},
                            "http_req_failed": {"value": 0},
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(HarnessError):
                load_metrics(summary)


if __name__ == "__main__":
    unittest.main()
