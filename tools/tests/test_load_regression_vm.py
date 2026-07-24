"""NFR-001 private 2GiB Nginx load-regression harness contracts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.errors import HarnessError
from tools.vpsguard_harness.load_regression import LoadMetrics
from tools.vpsguard_harness.load_regression_vm import _plan
from tools.vpsguard_harness.load_regression_vm_model import (
    VmLoadRegressionManifest,
    VmLoadRound,
    aggregate_rounds,
    verify_k6_binary,
)
from tools.vpsguard_harness.protection_pilot_model import Bundle


class VmLoadRegressionTests(unittest.TestCase):
    """The VM proof is private, fixed, paired and fail-closed."""

    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[2]
        self.manifest_path = self.root / "tests/vm/g7-bench-load-regression.json"

    def test_manifest_requires_private_exact_2gb_fixed_workload(self) -> None:
        manifest = VmLoadRegressionManifest.load(self.manifest_path)
        self.assertEqual(manifest.target_memory_kib, 2_097_152)
        self.assertEqual(manifest.vus, 50)
        self.assertEqual(manifest.duration_seconds, 15)
        self.assertEqual(manifest.think_time_ms, 100)
        self.assertEqual(manifest.rounds, 3)
        self.assertEqual(manifest.worker_threads, 2)
        self.assertEqual(manifest.confirmation, "isolated-vm:g7-test")

        raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        raw["target"]["private_ip"] = "203.0.113.10"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(HarnessError):
                VmLoadRegressionManifest.load(path)

    def test_aggregates_median_and_rejects_incomplete_rounds(self) -> None:
        rounds = [
            VmLoadRound(
                number=number,
                order=("direct", "guard") if number % 2 else ("guard", "direct"),
                direct=LoadMetrics(10.0 + number, 1_000.0, 0.0),
                guard=LoadMetrics(11.0 + number, 950.0, 0.0),
            )
            for number in range(1, 4)
        ]
        result = aggregate_rounds(rounds)
        self.assertTrue(result.passed)
        self.assertEqual(result.p95_overhead_ms, 1.0)
        self.assertEqual(result.throughput_reduction_percent, 5.0)
        with self.assertRaises(HarnessError):
            aggregate_rounds(rounds[:2])

    def test_rejects_wrong_k6_checksum_or_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "k6"
            binary.write_bytes(b"not-an-elf")
            with self.assertRaises(HarnessError):
                verify_k6_binary(binary, "0" * 64)

    def test_plan_names_exact_restore_and_public_preservation(self) -> None:
        manifest = VmLoadRegressionManifest.load(self.manifest_path)
        bundle = Bundle(path=Path("/tmp/bundle"), source_commit="a" * 40)
        plan = _plan(
            manifest,
            bundle,
            manifest.stage_base / bundle.source_commit,
            manifest.k6_sha256,
        )
        self.assertIn("stop_edge_remove_listener_restore_memory", plan["steps"])
        self.assertIn("public Nginx 80/443", plan["preserves"])
        proxy = (self.root / "tests/load/proxy.js").read_text(encoding="utf-8")
        self.assertIn("THINK_TIME_SECONDS || 0.1", proxy)


if __name__ == "__main__":
    unittest.main()
