"""OPS-006 isolated 2GB Apache uninstall harness contracts."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.uninstall_pilot import run_uninstall_pilot
from tools.vpsguard_harness.uninstall_pilot_model import (
    UninstallPilotError,
    UninstallPilotManifest,
)
from tools.vpsguard_harness.uninstall_pilot_remote import (
    generated_paths,
    require_post_uninstall,
    uninstall_environment,
)
from tools.vpsguard_harness.qga import GuestCommandResult


class UninstallPilotTest(unittest.TestCase):
    """Require private Apache bypass, bounded backup and exact-restore planning."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.tests_vm = self.root / "tests/vm"
        self.tests_vm.mkdir(parents=True)
        self.protection = self.tests_vm / "protection.json"
        self.endurance = self.tests_vm / "endurance.json"
        self.manifest = self.tests_vm / "uninstall.json"
        self.bundle = self.root / "bundle"
        self.evidence = self.root / "evidence/uninstall.json"
        self.write_protection()
        self.write_endurance()
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
                        "stage_base": "/home/gnuboard5/vpsguard-ops006-pilot",
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

    def write_endurance(self, *, ip: str = "192.168.0.143") -> None:
        self.endurance.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "protection_manifest": self.protection.name,
                    "public_probe": {
                        "url": "https://gnuboard5.local/",
                        "host": "gnuboard5.local",
                        "ip": ip,
                        "ca_certificate": None,
                        "expected_status": 200,
                    },
                    "execution": {
                        "cycles": 20,
                        "interval_ms": 100,
                        "max_outage_ms": 5_000,
                        "max_update_ms": 60_000,
                        "max_restore_ms": 10_000,
                    },
                }
            ),
            encoding="utf-8",
        )

    def write_manifest(
        self,
        *,
        ingress: str = "apache-public",
        max_uninstall_ms: int = 30_000,
        max_restore_ms: int = 30_000,
    ) -> None:
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "release_endurance_manifest": self.endurance.name,
                    "ingress": ingress,
                    "guest_probe_ca_certificate": (
                        "/etc/ssl/gnuboard5/gnuboard5.local.pem"
                    ),
                    "execution": {
                        "max_uninstall_ms": max_uninstall_ms,
                        "max_restore_ms": max_restore_ms,
                    },
                }
            ),
            encoding="utf-8",
        )

    def write_bundle(self) -> None:
        files = (
            "bin/vps-guard",
            "scripts/deployment-state.sh",
            "scripts/state-common.sh",
            "scripts/uninstall.sh",
            "ownership-manifest.txt",
            "gnuboard5/apache/gnuboard5-guarded.conf",
            "gnuboard5/apache/gnuboard5-bypass.conf",
            "gnuboard5/apache/vpsguard-origin.conf",
            "gnuboard5/apache/vpsguard-origin-ports.conf",
            "gnuboard5/vps-guard.enforce.toml",
        )
        checksums = []
        for relative in files:
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            content = f"fixture:{relative}\n".encode()
            path.write_bytes(content)
            checksums.append(f"{hashlib.sha256(content).hexdigest()}  ./{relative}")
        self.bundle.joinpath("BUILD-INFO.txt").write_text(
            "target=x86_64-unknown-linux-gnu\n"
            "version=0.1.0\n"
            "0123456789abcdef0123456789abcdef01234567\n",
            encoding="utf-8",
        )
        self.bundle.joinpath("SHA256SUMS").write_text(
            "\n".join(checksums) + "\n",
            encoding="utf-8",
        )

    def test_plan_is_2gb_apache_owned_only_and_restore_first(self) -> None:
        summary = run_uninstall_pilot(
            self.root,
            self.manifest,
            self.bundle,
            self.evidence,
            execute=False,
            confirmation=None,
        )
        self.assertIsNone(summary)
        plan = json.loads(self.evidence.with_suffix(".plan.json").read_text())
        self.assertEqual(plan["target"]["memory_kib"], 2_097_152)
        self.assertEqual(plan["target"]["ingress"], "apache-public")
        self.assertEqual(plan["budgets"]["probe_interval_ms"], 100)
        self.assertEqual(plan["budgets"]["max_outage_ms"], 5_000)
        self.assertIn("apply_owned_only_uninstall", plan["steps"])
        self.assertIn("restore_release_tree_and_typed_deployment_snapshot", plan["steps"])
        self.assertLess(
            plan["steps"].index("typed_apache_bypass"),
            plan["steps"].index(
                "snapshot_owned_deployment_at_apache_bypass_boundary"
            ),
        )
        self.assertLess(
            plan["steps"].index(
                "snapshot_owned_deployment_at_apache_bypass_boundary"
            ),
            plan["steps"].index("apply_owned_only_uninstall"),
        )
        self.assertFalse(plan["scans_site_tree"])
        self.assertFalse(plan["stores_credentials"])
        self.assertFalse(plan["stores_site_content"])

    def test_manifest_rejects_nginx_public_target_and_unbounded_budget(self) -> None:
        self.write_manifest(ingress="nginx-public")
        with self.assertRaises(UninstallPilotError):
            UninstallPilotManifest.load(self.root, self.manifest)
        self.write_manifest(max_uninstall_ms=30_001)
        with self.assertRaises(UninstallPilotError):
            UninstallPilotManifest.load(self.root, self.manifest)
        self.write_endurance(ip="8.8.8.8")
        self.write_manifest()
        with self.assertRaises(UninstallPilotError):
            UninstallPilotManifest.load(self.root, self.manifest)

    def test_uninstall_environment_requires_explicit_apache_bypass(self) -> None:
        manifest = UninstallPilotManifest.load(self.root, self.manifest)
        environment = uninstall_environment(manifest)
        self.assertIn(
            "VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only",
            environment,
        )
        self.assertIn("VPS_GUARD_BYPASS_VERIFIED=apache-public", environment)
        self.assertIn(
            "VPS_GUARD_UNINSTALL_PROBE_URL=https://gnuboard5.local/",
            environment,
        )
        self.assertIn(
            "VPS_GUARD_UNINSTALL_PROBE_CA="
            "/etc/ssl/gnuboard5/gnuboard5.local.pem",
            environment,
        )

    def test_generated_cleanup_paths_are_only_typed_cli_outputs(self) -> None:
        paths = generated_paths(
            "snapshot=/var/backups/vps-guard/deployments/deploy-1\n"
            "rollback_snapshot=/var/lib/vps-guard/backups/apache-ingress/apache-2\n"
            "transaction_state=/var/backups/vps-guard/transactions/"
            "deployment-restore-3/state.json\n"
        )
        self.assertEqual(
            paths,
            (
                "/var/backups/vps-guard/deployments/deploy-1",
                "/var/lib/vps-guard/backups/apache-ingress/apache-2",
                "/var/backups/vps-guard/transactions/deployment-restore-3",
            ),
        )

    def test_post_uninstall_accepts_removed_edge_unit(self) -> None:
        class RemovedEdgeGuest:
            def execute(
                self,
                argv: tuple[str, ...],
                *,
                accepted_exit_codes: tuple[int, ...] = (0,),
            ) -> GuestCommandResult:
                if argv[1:3] == ("is-active", "apache2.service"):
                    return GuestCommandResult(0, "active\n", "")
                if argv[1:3] == ("is-active", "vps-guard-edge.service"):
                    self.assert_exit(3, accepted_exit_codes)
                    return GuestCommandResult(3, "inactive\n", "")
                if argv[1:3] == ("is-enabled", "vps-guard-edge.service"):
                    self.assert_exit(4, accepted_exit_codes)
                    return GuestCommandResult(4, "not-found\n", "")
                return GuestCommandResult(0, "", "")

            @staticmethod
            def assert_exit(
                value: int,
                accepted_exit_codes: tuple[int, ...],
            ) -> None:
                if value not in accepted_exit_codes:
                    raise AssertionError(
                        f"exit {value} missing from {accepted_exit_codes}"
                    )

        self.assertTrue(require_post_uninstall(RemovedEdgeGuest())["owned_paths_absent"])


if __name__ == "__main__":
    unittest.main()
