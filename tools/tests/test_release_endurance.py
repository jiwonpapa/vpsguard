"""OPS-005 and OPS-010 2GB release endurance harness contracts."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.protection_pilot import Bundle, ProtectionPilotError
from tools.vpsguard_harness.release_endurance import (
    ProbeAvailability,
    ProbeSample,
    ReleaseEnduranceError,
    ReleaseEnduranceManifest,
    public_probe_command,
    run_release_endurance,
)


class ReleaseEnduranceTest(unittest.TestCase):
    """Require a private target, exact 20 cycles and bounded public outage."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.protection_manifest = self.root / "protection.json"
        self.endurance_manifest = self.root / "endurance.json"
        self.bundle = self.root / "bundle"
        self.evidence = self.root / "evidence/endurance.json"
        self.write_protection_manifest()
        self.write_endurance_manifest()
        self.write_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_protection_manifest(self) -> None:
        self.protection_manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": {
                        "host_alias": "gnuboard7",
                        "domain": "gnuboard5",
                        "guest_copy_target": "gnuboard5@192.168.0.143",
                        "stage_base": "/home/gnuboard5/vpsguard-ops010-endurance",
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

    def write_endurance_manifest(self, **changes: object) -> None:
        raw: dict[str, object] = {
            "schema_version": 1,
            "protection_manifest": self.protection_manifest.name,
            "public_probe": {
                "url": "https://gnuboard5.local/",
                "host": "gnuboard5.local",
                "ip": "192.168.0.143",
                "ca_certificate": None,
                "expected_status": 200,
            },
            "execution": {
                "cycles": 20,
                "interval_ms": 100,
                "max_outage_ms": 5_000,
            },
        }
        raw.update(changes)
        self.endurance_manifest.write_text(json.dumps(raw), encoding="utf-8")

    def write_bundle(self) -> None:
        binary = self.bundle / "bin/vps-guard"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"verified endurance fixture")
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

    def test_plan_requires_twenty_cycles_and_public_probe_preservation(self) -> None:
        summary = run_release_endurance(
            self.root,
            self.endurance_manifest,
            self.bundle,
            self.evidence,
            execute=False,
            confirmation=None,
        )
        self.assertIsNone(summary)
        plan = json.loads(self.evidence.with_suffix(".plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["execution"]["cycles"], 20)
        self.assertEqual(plan["execution"]["interval_ms"], 100)
        self.assertEqual(plan["execution"]["max_outage_ms"], 5_000)
        self.assertIn("restore_each_deployment_snapshot", plan["steps"])
        self.assertIn("SSH", plan["preserves"])
        self.assertFalse(plan["stores_credentials"])

    def test_public_probe_is_exact_tls_body_free_and_never_insecure(self) -> None:
        manifest = ReleaseEnduranceManifest.load(self.root, self.endurance_manifest)
        command = public_probe_command(manifest)
        self.assertIn("gnuboard5.local:443:192.168.0.143", command)
        self.assertIn("/dev/null", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--data", command)
        self.assertNotIn("--request", command)

    def test_manifest_rejects_public_mismatched_and_unbounded_targets(self) -> None:
        self.write_endurance_manifest(
            public_probe={
                "url": "https://gnuboard5.local/",
                "host": "gnuboard5.local",
                "ip": "8.8.8.8",
                "ca_certificate": None,
                "expected_status": 200,
            }
        )
        with self.assertRaises(ReleaseEnduranceError):
            ReleaseEnduranceManifest.load(self.root, self.endurance_manifest)

        self.write_endurance_manifest(
            execution={"cycles": 21, "interval_ms": 99, "max_outage_ms": 5_001}
        )
        with self.assertRaises(ReleaseEnduranceError):
            ReleaseEnduranceManifest.load(self.root, self.endurance_manifest)

        self.write_endurance_manifest(
            public_probe={
                "url": "https://other.local/",
                "host": "other.local",
                "ip": "192.168.0.143",
                "ca_certificate": None,
                "expected_status": 200,
            }
        )
        with self.assertRaises(ReleaseEnduranceError):
            ReleaseEnduranceManifest.load(self.root, self.endurance_manifest)

    def test_probe_availability_measures_real_consecutive_outage(self) -> None:
        availability = ProbeAvailability(expected_status=200)
        availability.observe(ProbeSample(0, 10, 200, 0))
        availability.observe(ProbeSample(100, 150, 502, 0))
        availability.observe(ProbeSample(200, 260, 0, 28))
        availability.observe(ProbeSample(300, 330, 200, 0))
        summary = availability.finish(400)

        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["successes"], 2)
        self.assertEqual(summary["failures"], 2)
        self.assertEqual(summary["max_outage_ms"], 230)
        self.assertEqual(summary["status_counts"], {"0": 1, "200": 2, "502": 1})
        self.assertEqual(summary["final_status"], 200)

    def test_bundle_is_verified_before_any_endurance_plan(self) -> None:
        self.bundle.joinpath("bin/vps-guard").write_bytes(b"tampered")
        with self.assertRaises(ReleaseEnduranceError):
            run_release_endurance(
                self.root,
                self.endurance_manifest,
                self.bundle,
                self.evidence,
                execute=False,
                confirmation=None,
            )
        with self.assertRaises(ProtectionPilotError):
            Bundle.verify(self.bundle)


if __name__ == "__main__":
    unittest.main()
