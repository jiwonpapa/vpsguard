"""NFR-014 VM adversarial harness regression tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.vm_lab import (
    VmLabError,
    VmLabManifest,
    public_probe_command,
    run_public_probe_timeline,
    run_vm_lab,
)


class VmLabTest(unittest.TestCase):
    """Keep the lab private, digest pinned and secret/body free."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.ca = self.root / "rootCA.pem"
        self.ca.write_text("public ca\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self, **changes: object) -> Path:
        raw: dict[str, object] = {
            "schema_version": 1,
            "target": {
                "url": "https://gnuboard5.local/",
                "host": "gnuboard5.local",
                "ip": "192.168.122.9",
            },
            "ca_certificate": str(self.ca),
            "images": {"oha": f"ghcr.io/hatoo/oha@sha256:{'a' * 64}"},
            "scenarios": [
                {
                    "name": "normal",
                    "tool": "oha",
                    "arguments": ["--no-tui", "--json", "{target_url}"],
                    "timeout_seconds": 30,
                    "output_format": "json",
                }
            ],
        }
        raw.update(changes)
        path = self.root / "toolkit.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        return path

    def test_plan_uses_argv_only_pinned_image_and_public_ca(self) -> None:
        manifest = VmLabManifest.load(self.manifest())
        command = manifest.command(manifest.scenarios[0], self.root, self.root / "normal.json")
        self.assertEqual(command.argv[0:3], ("docker", "run", "--rm"))
        self.assertTrue(any("@sha256:" in argument for argument in command.argv))
        self.assertNotIn("shell", " ".join(command.argv).lower())
        run_vm_lab(self.root, self.root / "toolkit.json", self.root / "evidence", execute=False)
        plan = (self.root / "evidence/plan.json").read_text(encoding="utf-8")
        self.assertIn('"stores_credentials": false', plan)
        self.assertIn('"stores_request_bodies": false', plan)

    def test_public_target_and_unpinned_image_are_rejected(self) -> None:
        public = self.manifest(
            target={"url": "https://example.com/", "host": "example.com", "ip": "8.8.8.8"}
        )
        with self.assertRaises(VmLabError):
            VmLabManifest.load(public)
        unpinned = self.manifest(images={"oha": "ghcr.io/hatoo/oha:latest"})
        with self.assertRaises(VmLabError):
            VmLabManifest.load(unpinned)

    def test_private_key_path_and_evidence_escape_are_rejected(self) -> None:
        key = self.root / "rootCA-key.pem"
        key.write_text("secret", encoding="utf-8")
        manifest = self.manifest(ca_certificate=str(key))
        with self.assertRaises(VmLabError):
            VmLabManifest.load(manifest)
        valid = self.manifest()
        with self.assertRaises(VmLabError):
            run_vm_lab(self.root, valid, self.root.parent / "escape", execute=False)

    def test_exact_scenario_filter_prevents_rate_limit_state_contamination(self) -> None:
        manifest = self.manifest()
        run_vm_lab(
            self.root,
            manifest,
            self.root / "evidence",
            execute=False,
            scenario_name="normal",
        )
        plan = json.loads((self.root / "evidence/plan.json").read_text(encoding="utf-8"))
        self.assertEqual([scenario["name"] for scenario in plan["scenarios"]], ["normal"])
        with self.assertRaises(VmLabError):
            run_vm_lab(
                self.root,
                manifest,
                self.root / "missing",
                execute=False,
                scenario_name="missing",
            )

    def test_public_probe_is_body_free_and_bounded(self) -> None:
        manifest_path = self.manifest()
        manifest = VmLabManifest.load(manifest_path)
        command = public_probe_command(manifest)
        self.assertIn("/dev/null", command)
        self.assertIn("--cacert", command)
        self.assertIn("gnuboard5.local:443:192.168.122.9", command)
        with self.assertRaises(VmLabError):
            run_public_probe_timeline(
                self.root,
                manifest_path,
                self.root / "probe.jsonl",
                duration_seconds=0,
                interval_ms=99,
            )


if __name__ == "__main__":
    unittest.main()
