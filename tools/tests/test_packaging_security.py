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


if __name__ == "__main__":
    unittest.main()
