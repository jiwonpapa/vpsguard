"""DET-014 isolated 2GB host-pressure harness and probe contracts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.host_pressure import (
    HostPressureError,
    HostPressureManifest,
    run_host_pressure,
)


def _load_probe() -> object:
    path = Path(__file__).resolve().parents[1] / "vm/host-pressure-probe.py"
    spec = importlib.util.spec_from_file_location("host_pressure_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("host pressure probe module loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


probe = _load_probe()


class HostPressureTest(unittest.TestCase):
    """Require private 2GB execution, bounded load and deterministic recovery."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.protection = self.root / "protection.json"
        self.manifest = self.root / "pressure.json"
        self.evidence = self.root / "evidence/pressure.json"
        self.bundle = self.root / "bundle"
        self.write_protection()
        self.write_manifest()
        self.write_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_protection(self) -> None:
        self.protection.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": {
                        "host_alias": "gnuboard7",
                        "domain": "gnuboard5",
                        "guest_copy_target": "gnuboard5@192.168.0.143",
                        "stage_base": "/home/gnuboard5/vpsguard-det014-pressure",
                        "target_memory_kib": 2_097_152,
                    },
                    "runtime": {
                        "current_release_path": "/usr/local/lib/vps-guard/current",
                        "services": [
                            "apache2.service",
                            "vps-guard-edge.service",
                            "vps-guard-control.service",
                        ],
                    },
                    "management": {
                        "control_url": "http://127.0.0.1:7727",
                        "management_host": "192.168.0.143:7443",
                        "management_origin": "https://192.168.0.143:7443",
                        "admin_socket": "/run/vps-guard/admin.sock",
                        "edge_url": "http://127.0.0.1:18080",
                        "edge_host": "gnuboard5.local",
                    },
                }
            ),
            encoding="utf-8",
        )

    def write_manifest(self, **changes: object) -> None:
        value: dict[str, object] = {
            "schema_version": 1,
            "protection_manifest": self.protection.name,
            "public_probe": {
                "url": "https://gnuboard5.local/",
                "host": "gnuboard5.local",
                "ip": "192.168.0.143",
                "ca_certificate": None,
                "expected_status": 200,
            },
            "execution": {
                "pressure_seconds": 40,
                "recovery_timeout_seconds": 60,
                "sample_interval_ms": 1_000,
                "request_interval_ms": 2_000,
                "cpu_workers": 4,
                "probe_interval_ms": 100,
                "max_outage_ms": 5_000,
            },
        }
        value.update(changes)
        self.manifest.write_text(json.dumps(value), encoding="utf-8")

    def write_bundle(self) -> None:
        binary = self.bundle / "bin/vps-guard"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"verified pressure fixture")
        self.bundle.joinpath("BUILD-INFO.txt").write_text(
            "target=x86_64-unknown-linux-gnu\n"
            "version=0.1.0\n"
            "0123456789abcdef0123456789abcdef01234567\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.bundle.joinpath("SHA256SUMS").write_text(
            f"{digest}  ./bin/vps-guard\n",
            encoding="utf-8",
        )

    def test_plan_is_private_bounded_and_preserves_vm_state(self) -> None:
        summary = run_host_pressure(
            self.root,
            self.manifest,
            self.bundle,
            self.evidence,
            execute=False,
            confirmation=None,
        )
        self.assertIsNone(summary)
        plan = json.loads(self.evidence.with_suffix(".plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["execution"]["pressure_seconds"], 40)
        self.assertEqual(plan["execution"]["cpu_workers"], 4)
        self.assertEqual(
            plan["source_commit"],
            "0123456789abcdef0123456789abcdef01234567",
        )
        self.assertIn("/det014-host-pressure/", plan["target"]["stage"])
        self.assertTrue(
            plan["target"]["stage"].endswith(
                "/0123456789abcdef0123456789abcdef01234567"
            )
        )
        self.assertEqual(plan["public_probe"]["interval_ms"], 100)
        self.assertIn("restore_original_memory_and_balloon", plan["steps"])
        self.assertFalse(plan["stores_response_bodies"])

    def test_manifest_rejects_public_target_and_unbounded_load(self) -> None:
        self.write_manifest(
            public_probe={
                "url": "https://gnuboard5.local/",
                "host": "gnuboard5.local",
                "ip": "8.8.8.8",
                "ca_certificate": None,
                "expected_status": 200,
            }
        )
        with self.assertRaises(HostPressureError):
            HostPressureManifest.load(self.root, self.manifest)
        self.write_manifest(
            execution={
                "pressure_seconds": 121,
                "recovery_timeout_seconds": 121,
                "sample_interval_ms": 999,
                "request_interval_ms": 999,
                "cpu_workers": 65,
                "probe_interval_ms": 99,
                "max_outage_ms": 5_001,
            }
        )
        with self.assertRaises(HostPressureError):
            HostPressureManifest.load(self.root, self.manifest)

    def test_proc_cpu_delta_and_memory_parser_are_bounded(self) -> None:
        previous = "cpu  100 0 100 800 0 0 0 0\ncpu0 1 0 1 8\n"
        current = "cpu  300 0 300 900 0 0 0 0\ncpu0 3 0 3 9\n"
        self.assertEqual(probe.cpu_usage_percent(previous, current), 80)
        memory = probe.memory_snapshot(
            "MemTotal: 1840328 kB\nMemAvailable: 460082 kB\n"
            "SwapTotal: 1024 kB\nSwapFree: 512 kB\n"
        )
        self.assertEqual(memory["memory_total_bytes"], 1_840_328 * 1024)
        self.assertEqual(memory["memory_available_bytes"], 460_082 * 1024)

    def test_timeline_requires_local_guard_pressure_alignment_and_recovery(self) -> None:
        timeline = [
            {"phase": "baseline", "mode": "NORMAL", "direct_cpu_percent": 2, "api_cpu_percent": 3},
            {"phase": "pressure", "mode": "WATCH", "direct_cpu_percent": 99, "api_cpu_percent": 98},
            {
                "phase": "pressure",
                "mode": "LOCAL_GUARD",
                "direct_cpu_percent": 100,
                "api_cpu_percent": 100,
            },
            {
                "phase": "recovery",
                "mode": "RECOVERING",
                "direct_cpu_percent": 5,
                "api_cpu_percent": 4,
            },
            {"phase": "recovery", "mode": "NORMAL", "direct_cpu_percent": 4, "api_cpu_percent": 3},
        ]
        for sample in timeline:
            sample["direct_memory_total_bytes"] = 1_884_495_872
            sample["api_memory_total_bytes"] = 1_884_495_872
        summary = probe.summarize_timeline(timeline, provider_status="unavailable")
        self.assertTrue(summary["local_guard_observed"])
        self.assertTrue(summary["normal_recovered"])
        self.assertEqual(summary["max_cpu_alignment_delta"], 1)
        with self.assertRaises(probe.ProbeError):
            probe.summarize_timeline(timeline[:2], provider_status="unavailable")

    def test_cpu_worker_command_is_fixed_and_body_free(self) -> None:
        self.assertEqual(
            probe.CPU_WORKER_COMMAND,
            ("/usr/bin/sha256sum", "/dev/zero"),
        )


if __name__ == "__main__":
    unittest.main()
