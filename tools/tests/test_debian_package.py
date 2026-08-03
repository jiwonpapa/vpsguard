"""Cross-platform Debian package generation contracts."""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.debian_package import DebianPackageError, build_package


class DebianPackageTests(unittest.TestCase):
    """A package must install binaries but preserve existing configuration."""

    source_commit = "0123456789abcdef0123456789abcdef01234567"

    def test_builds_valid_ar_with_services_and_non_overwriting_postinst(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root, "x86_64-unknown-linux-gnu")

            package = build_package(
                bundle,
                root / "vpsguard.deb",
                expected_commit=self.source_commit,
            )
            members = self._ar_members(package.read_bytes())

            self.assertEqual(members["debian-binary"], b"2.0\n")
            with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as archive:
                control = archive.extractfile("./control")
                postinst = archive.extractfile("./postinst")
                self.assertIsNotNone(control)
                self.assertIsNotNone(postinst)
                self.assertIn(b"Architecture: amd64", control.read())
                script = postinst.read()
                self.assertIn(b"if [ ! -e /etc/vps-guard/config.toml ]", script)
                self.assertIn(b"if [ -d /run/systemd/system ]", script)
                self.assertNotIn(b"systemctl enable", script)
                self.assertNotIn(b"systemctl start", script)
            with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("./usr/local/bin/vps-guard", names)
                self.assertIn("./etc/systemd/system/vps-guard-edge.service", names)
                self.assertIn("./usr/share/doc/vpsguard/BUILD-INFO.txt", names)
                self.assertNotIn("./etc/vps-guard/config.toml", names)

    def test_maps_arm_bundle_and_rejects_unknown_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arm = self._bundle(root / "arm", "aarch64-unknown-linux-gnu")
            package = build_package(
                arm,
                root / "arm.deb",
                expected_commit=self.source_commit,
            )
            members = self._ar_members(package.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as archive:
                control = archive.extractfile("./control")
                self.assertIsNotNone(control)
                self.assertIn(b"Architecture: arm64", control.read())

            unknown = self._bundle(root / "unknown", "riscv64-unknown-linux-gnu")
            with self.assertRaises(DebianPackageError):
                build_package(
                    unknown,
                    root / "unknown.deb",
                    expected_commit=self.source_commit,
                )

    def test_rejects_bundle_built_from_a_different_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root, "x86_64-unknown-linux-gnu")

            with self.assertRaises(DebianPackageError) as raised:
                build_package(
                    bundle,
                    root / "stale.deb",
                    expected_commit="f" * 40,
                )

            self.assertEqual(
                raised.exception.code,
                "DEBIAN_BUNDLE_COMMIT_MISMATCH",
            )
            self.assertFalse((root / "stale.deb").exists())

    def test_rejects_a_bundle_with_modified_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root, "x86_64-unknown-linux-gnu")
            (bundle / "bin/vps-guard").write_bytes(b"tampered")

            with self.assertRaises(DebianPackageError) as raised:
                build_package(
                    bundle,
                    root / "tampered.deb",
                    expected_commit=self.source_commit,
                )

            self.assertEqual(
                raised.exception.code,
                "DEBIAN_BUNDLE_CHECKSUM_MISMATCH",
            )
            self.assertFalse((root / "tampered.deb").exists())

    @staticmethod
    def _bundle(root: Path, target: str) -> Path:
        bundle = root / "vpsguard-0.1.0"
        for directory in (
            "bin",
            "systemd/vps-guard-control.service.d",
            "tmpfiles",
            "pam",
            "certbot",
        ):
            (bundle / directory).mkdir(parents=True, exist_ok=True)
        for binary in ("vps-guard", "vps-guard-control", "vps-guard-privileged", "vps-guard-edge"):
            (bundle / "bin" / binary).write_bytes(b"binary")
        for unit in (
            "vps-guard-control.service",
            "vps-guard-edge.service",
            "vps-guard-privileged.service",
            "vps-guard-privileged.socket",
        ):
            (bundle / "systemd" / unit).write_text("[Unit]\n", encoding="utf-8")
        (bundle / "systemd/vps-guard-control.service.d/20-cloudflare-credential.conf").write_text(
            "[Service]\n", encoding="utf-8"
        )
        (bundle / "tmpfiles/vps-guard.conf").write_text("d var 0750 root root -\n", encoding="utf-8")
        (bundle / "pam/vps-guard").write_text("auth required pam_unix.so\n", encoding="utf-8")
        (bundle / "certbot/vps-guard-deploy-hook").write_text("#!/bin/sh\n", encoding="utf-8")
        (bundle / "vps-guard.example.toml").write_text("[edge]\n", encoding="utf-8")
        (bundle / "ownership-manifest.txt").write_text("owned\n", encoding="utf-8")
        (bundle / "BUILD-INFO.txt").write_text(
            f"target={target}\nversion=0.1.0\ncommit={DebianPackageTests.source_commit}\n",
            encoding="utf-8",
        )
        checksums = (
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"./{path.relative_to(bundle)}"
            for path in sorted(bundle.rglob("*"))
            if path.is_file()
        )
        (bundle / "SHA256SUMS").write_text(
            "\n".join(checksums) + "\n",
            encoding="utf-8",
        )
        return bundle

    @staticmethod
    def _ar_members(content: bytes) -> dict[str, bytes]:
        if not content.startswith(b"!<arch>\n"):
            raise AssertionError("ar magic missing")
        members: dict[str, bytes] = {}
        offset = 8
        while offset < len(content):
            header = content[offset : offset + 60]
            name = header[:16].decode("ascii").strip().removesuffix("/")
            size = int(header[48:58].decode("ascii").strip())
            start = offset + 60
            members[name] = content[start : start + size]
            offset = start + size + (size % 2)
        return members


if __name__ == "__main__":
    unittest.main()
