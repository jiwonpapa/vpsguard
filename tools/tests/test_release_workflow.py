"""OPS-007 multi-architecture artifact execution workflow contracts."""

from __future__ import annotations

import unittest
import tomllib
from pathlib import Path


class ReleaseWorkflowTests(unittest.TestCase):
    """Artifacts must execute before attestation and upload."""

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
    ).read_text(encoding="utf-8")
    cross = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "Cross.toml").read_text(encoding="utf-8")
    )

    def test_both_linux_architectures_execute_under_qemu(self) -> None:
        self.assertIn("x86_64-unknown-linux-gnu", self.workflow)
        self.assertIn("aarch64-unknown-linux-gnu", self.workflow)
        self.assertIn(
            "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
            self.workflow,
        )
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

    def test_cross_images_install_host_bindgen_and_target_pam_dependencies(self) -> None:
        for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            commands = self.cross["target"][target]["pre-build"]
            self.assertTrue(any("$CROSS_DEB_ARCH" in command for command in commands))
            install = next(command for command in commands if "apt-get" in command)
            self.assertIn("libclang-dev", install)
            self.assertIn("libpam0g-dev:$CROSS_DEB_ARCH", install)


if __name__ == "__main__":
    unittest.main()
