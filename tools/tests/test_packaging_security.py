"""ACT-013/SEC-015 privileged helper packaging regression contracts."""

from __future__ import annotations

import unittest
from pathlib import Path


class PrivilegedPackagingTests(unittest.TestCase):
    """Keep PAM and UFW authority behind a systemd-owned local socket."""

    root = Path(__file__).resolve().parents[2]

    def test_socket_is_not_world_writable_and_has_a_protected_parent(self) -> None:
        socket = (self.root / "packaging/systemd/vps-guard-privileged.socket").read_text(
            encoding="utf-8"
        )
        tmpfiles = (self.root / "packaging/tmpfiles/vps-guard.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("ListenStream=/run/vps-guard-privileged/control.sock", socket)
        self.assertIn("SocketGroup=vps-guard", socket)
        self.assertIn("SocketMode=0660", socket)
        self.assertIn("DirectoryMode=0750", socket)
        self.assertIn("d /run/vps-guard-privileged 0750 root vps-guard -", tmpfiles)

    def test_helper_cannot_change_identity_and_control_has_no_firewall_capability(self) -> None:
        helper = (self.root / "packaging/systemd/vps-guard-privileged.service").read_text(
            encoding="utf-8"
        )
        control = (self.root / "packaging/systemd/vps-guard-control.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("Requires=vps-guard-privileged.socket", helper)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH", helper)
        self.assertNotIn("CAP_SETUID", helper)
        self.assertNotIn("CAP_SETGID", helper)
        self.assertNotIn("CAP_NET_ADMIN", control)

    def test_all_units_bound_logs_and_release_metadata_is_embedded(self) -> None:
        units = [
            self.root / "packaging/systemd/vps-guard-edge.service",
            self.root / "packaging/systemd/vps-guard-control.service",
            self.root / "packaging/systemd/vps-guard-privileged.service",
        ]
        for path in units:
            unit = path.read_text(encoding="utf-8")
            self.assertIn("LogRateLimitIntervalSec=30s", unit)
            self.assertIn("LogRateLimitBurst=2000", unit)
        self.assertIn("pingora=off", units[0].read_text(encoding="utf-8"))
        release = (self.root / "scripts/build-release.sh").read_text(encoding="utf-8")
        edge = (self.root / "crates/guard-edge/src/main.rs").read_text(encoding="utf-8")
        command = (self.root / "crates/guard-system/src/command.rs").read_text(
            encoding="utf-8"
        )
        api = (self.root / "crates/guard-control/src/api.rs").read_text(encoding="utf-8")
        self.assertIn("VPS_GUARD_BUILD_COMMIT", release)
        self.assertIn('option_env!("VPS_GUARD_BUILD_COMMIT")', edge)
        self.assertIn("redacted command stderr", command)
        self.assertIn('"/api/v1/bots"', api)


if __name__ == "__main__":
    unittest.main()
