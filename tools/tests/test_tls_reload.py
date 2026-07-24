"""TLS-002 isolated 2GB certificate reload harness contracts."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from tools.vpsguard_harness.tls_reload import run_tls_reload
from tools.vpsguard_harness.tls_reload_model import (
    TlsReloadError,
    TlsReloadManifest,
)
from tools.vpsguard_harness.tls_reload_probe import (
    TlsProbeTimeline,
    inflight_request_chunks,
)
from tools.vpsguard_harness.tls_reload_remote import (
    stage_reload_command,
    wait_service_active,
)


class TlsReloadTest(unittest.TestCase):
    """Require a private exact target, body-free probe and restore-first plan."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.tests_vm = self.root / "tests/vm"
        self.tests_vm.mkdir(parents=True)
        self.protection = self.tests_vm / "protection.json"
        self.manifest = self.tests_vm / "tls-reload.json"
        self.public_manifest = self.tests_vm / "gnuboard5-release-endurance.json"
        self.bundle = self.root / "bundle"
        self.evidence = self.root / "evidence/tls-reload.json"
        self.write_protection()
        self.write_manifest()
        self.write_public_manifest()
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
                        "stage_base": "/home/gnuboard5/vpsguard-ui018-pilot",
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

    def write_manifest(self, **probe_changes: object) -> None:
        probe: dict[str, object] = {
            "url": "https://gnuboard5.local:19443/",
            "host": "gnuboard5.local",
            "ip": "192.168.0.143",
            "port": 19_443,
            "interval_ms": 100,
            "max_outage_ms": 0,
            "drain_wait_seconds": 7,
        }
        probe.update(probe_changes)
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "protection_manifest": self.protection.name,
                    "probe": probe,
                }
            ),
            encoding="utf-8",
        )

    def write_public_manifest(self) -> None:
        self.public_manifest.write_text(
            json.dumps(
                {
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

    def write_bundle(self) -> None:
        binaries = {
            "bin/vps-guard": b"verified TLS CLI fixture",
            "bin/vps-guard-edge": b"verified TLS edge fixture",
        }
        checksums = []
        for relative, content in binaries.items():
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
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

    def test_plan_is_2gb_zero_outage_and_restore_first(self) -> None:
        summary = run_tls_reload(
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
        self.assertEqual(plan["target"]["test_listener"], 19_443)
        self.assertEqual(
            plan["target"]["transport"],
            "SSH local forwarding to guest loopback",
        )
        self.assertEqual(plan["budgets"]["probe_interval_ms"], 100)
        self.assertEqual(
            plan["budgets"]["public_preservation_interval_ms"],
            1_000,
        )
        self.assertEqual(plan["budgets"]["max_outage_ms"], 0)
        self.assertIn("wait_old_worker_exit", plan["steps"])
        self.assertIn("public_80_443", plan["preserves"])
        self.assertFalse(plan["stores_credentials"])
        self.assertFalse(plan["stores_request_bodies"])

    def test_probe_is_exact_tls_body_free_and_never_insecure(self) -> None:
        manifest = TlsReloadManifest.load(self.root, self.manifest)
        timeline = TlsProbeTimeline(
            self.root,
            manifest,
            self.root / "ephemeral-ca.pem",
            self.root / "probe.jsonl",
            connect_ip="127.0.0.1",
        )
        command = timeline.command()
        self.assertIn("gnuboard5.local:19443:127.0.0.1", command)
        self.assertIn("--cacert", command)
        self.assertIn("/dev/null", command)
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--data", command)
        self.assertNotIn("--request", command)

    def test_manifest_rejects_public_mismatch_and_nonzero_outage(self) -> None:
        self.write_manifest(ip="8.8.8.8")
        with self.assertRaises(TlsReloadError):
            TlsReloadManifest.load(self.root, self.manifest)
        self.write_manifest(max_outage_ms=1)
        with self.assertRaises(TlsReloadError):
            TlsReloadManifest.load(self.root, self.manifest)
        self.write_manifest(port=443, url="https://gnuboard5.local/")
        with self.assertRaises(TlsReloadError):
            TlsReloadManifest.load(self.root, self.manifest)

    def test_probe_service_uses_supervisor_and_hup_reload(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        unit = (repository / "tools/vm/vps-guard-tls-probe.service").read_text()
        config = (repository / "tools/vm/tls-reload-config.toml").read_text()
        self.assertIn("vps-guard-edge --supervisor", unit)
        self.assertIn("ExecReload=/bin/kill -HUP $MAINPID", unit)
        self.assertIn(
            "ExecStart=/opt/vps-guard-tls-probe/vps-guard-edge",
            unit,
        )
        self.assertNotIn(
            "ExecStart=/run/vps-guard-tls-probe/vps-guard-edge",
            unit,
        )
        self.assertIn('https_bind = "127.0.0.1:19443"', config)
        self.assertIn('address = "127.0.0.1:18081"', config)
        self.assertIn('management = "manual"', config)
        self.assertIn(
            'cert_file = "/opt/vps-guard-tls-probe/initial/fullchain.pem"',
            config,
        )

    def test_service_readiness_waits_through_activating_state(self) -> None:
        @dataclass(frozen=True)
        class Result:
            stdout: str

        class Guest:
            def __init__(self) -> None:
                self.states = iter(("activating", "active"))

            def execute(
                self,
                _argv: tuple[str, ...],
                *,
                accepted_exit_codes: tuple[int, ...],
            ) -> Result:
                self.asserted_codes = accepted_exit_codes
                return Result(stdout=next(self.states))

        guest = Guest()
        wait_service_active(guest)  # type: ignore[arg-type]
        self.assertEqual(guest.asserted_codes, (0, 3))

    def test_stage_command_uses_executable_install_not_noexec_runtime(self) -> None:
        manifest = TlsReloadManifest.load(self.root, self.manifest)
        command = stage_reload_command(manifest)
        self.assertEqual(
            command[0],
            "/opt/vps-guard-tls-probe/vps-guard",
        )
        self.assertNotIn("/run/vps-guard-tls-probe/vps-guard", command)
        self.assertIn("/opt/vps-guard-tls-probe/next/fullchain.pem", command)
        self.assertIn("/opt/vps-guard-tls-probe/next/privkey.pem", command)

    def test_drain_probe_is_bounded_and_inflight_before_reload(self) -> None:
        initial, finish = inflight_request_chunks("gnuboard5.local")
        self.assertIn(
            b"POST /__vpsguard_tls_drain_probe__ HTTP/1.1\r\n",
            initial,
        )
        self.assertIn(b"Host: gnuboard5.local\r\n", initial)
        self.assertIn(b"\r\n\r\n", initial)
        self.assertIn(b"Content-Length: 32\r\n", initial)
        body_prefix = initial.split(b"\r\n\r\n", maxsplit=1)[1]
        self.assertEqual(len(body_prefix), 1)
        self.assertEqual(len(body_prefix + finish), 32)
        self.assertEqual(set(body_prefix + finish), {ord("x")})


if __name__ == "__main__":
    unittest.main()
