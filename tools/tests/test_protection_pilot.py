"""UI-018 isolated 2GB VM pilot plan and bundle contract tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.protection_pilot import (
    Bundle,
    ProtectionPilotError,
    ProtectionPilotManifest,
    run_protection_pilot,
)


class ProtectionPilotTest(unittest.TestCase):
    """Reject public targets, unverified bundles and unbounded execution."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.manifest_path = self.root / "pilot.json"
        self.bundle = self.root / "bundle"
        self.evidence = self.root / "evidence/pilot.json"
        self.write_manifest()
        self.write_bundle()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_manifest(self, *, ip: str = "192.168.0.143", memory: int = 2_097_152) -> None:
        self.manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": {
                        "host_alias": "gnuboard7",
                        "domain": "gnuboard5",
                        "guest_copy_target": f"gnuboard5@{ip}",
                        "stage_base": "/home/gnuboard5/vpsguard-ui018-pilot",
                        "target_memory_kib": memory,
                    },
                    "runtime": {
                        "current_release_path": "/usr/local/lib/vps-guard/current",
                        "services": [
                            "apache2.service",
                            "vps-guard-edge.service",
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

    def write_bundle(self) -> None:
        binary = self.bundle / "bin/vps-guard"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"verified fixture")
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

    def test_plan_verifies_bundle_and_records_restore_sequence(self) -> None:
        summary = run_protection_pilot(
            self.root,
            self.manifest_path,
            self.bundle,
            self.evidence,
            execute=False,
            confirmation=None,
        )
        self.assertIsNone(summary)
        plan = json.loads(self.evidence.with_suffix(".plan.json").read_text(encoding="utf-8"))
        self.assertEqual(plan["confirmation"], "isolated-vm:gnuboard5")
        self.assertIn("restore_deployment_snapshot", plan["steps"])
        self.assertIn("restore_original_memory", plan["steps"])
        self.assertFalse(plan["stores_credentials"])

    def test_public_guest_and_non_2gb_target_are_rejected(self) -> None:
        self.write_manifest(ip="8.8.8.8")
        with self.assertRaises(ProtectionPilotError):
            ProtectionPilotManifest.load(self.manifest_path)
        self.write_manifest(memory=4_194_304)
        with self.assertRaises(ProtectionPilotError):
            ProtectionPilotManifest.load(self.manifest_path)

    def test_checksum_mismatch_and_stage_escape_are_rejected(self) -> None:
        self.bundle.joinpath("bin/vps-guard").write_bytes(b"tampered")
        with self.assertRaises(ProtectionPilotError):
            Bundle.verify(self.bundle)
        self.write_bundle()
        raw = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        raw["target"]["stage_base"] = "/tmp/pilot"
        self.manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ProtectionPilotError):
            ProtectionPilotManifest.load(self.manifest_path)


if __name__ == "__main__":
    unittest.main()
