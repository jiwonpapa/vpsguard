"""OPS-007 multi-architecture artifact execution workflow contracts."""

from __future__ import annotations

import unittest
from pathlib import Path


class ReleaseWorkflowTests(unittest.TestCase):
    """Artifacts must execute before attestation and upload."""

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
    ).read_text(encoding="utf-8")

    def test_both_linux_architectures_build_on_matching_native_runners(self) -> None:
        self.assertIn("x86_64-unknown-linux-gnu", self.workflow)
        self.assertIn("aarch64-unknown-linux-gnu", self.workflow)
        self.assertIn("runner: ubuntu-24.04", self.workflow)
        self.assertIn("runner: ubuntu-24.04-arm", self.workflow)
        self.assertIn("runs-on: ${{ matrix.runner }}", self.workflow)
        self.assertNotIn("setup-qemu", self.workflow)
        self.assertNotIn("CARGO_BUILD_TOOL: cross", self.workflow)
        self.assertIn('platform="linux/amd64"', self.workflow)
        self.assertIn('platform="linux/arm64"', self.workflow)
        self.assertIn('docker run --rm --platform "${platform}"', self.workflow)

    def test_every_packaged_binary_and_config_execute_before_upload(self) -> None:
        execution = self.workflow.index("- name: Execute every packaged binary")
        attestation = self.workflow.index("actions/attest-build-provenance")
        upload = self.workflow.index("actions/upload-artifact")
        self.assertLess(execution, attestation)
        self.assertLess(attestation, upload)
        self.assertIn(
            "for binary in vps-guard vps-guard-control "
            "vps-guard-privileged vps-guard-edge",
            self.workflow,
        )
        self.assertIn(
            "./bin/vps-guard check-config --config ./vps-guard.example.toml",
            self.workflow,
        )

    def test_native_runners_install_bindgen_and_pam_dependencies(self) -> None:
        self.assertIn(
            "sudo apt-get update && sudo apt-get install --yes "
            "libclang-dev libpam0g-dev",
            self.workflow,
        )
        self.assertIn("tool: cargo-cyclonedx", self.workflow)


if __name__ == "__main__":
    unittest.main()
