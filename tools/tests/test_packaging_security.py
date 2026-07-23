"""ACT-013/SEC-015 privileged helper packaging regression contracts."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.vpsguard_harness.ops import _remaining_systemd_verify_errors


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
        self.assertIn("d /var/lib/vps-guard/pam 0700 root root -", tmpfiles)

    def test_pam_password_and_sealed_mfa_are_separate_and_update_owned(self) -> None:
        pam = (self.root / "packaging/pam/vps-guard").read_text(encoding="utf-8")
        update = (self.root / "scripts/update-release.sh").read_text(encoding="utf-8")
        probe = (self.root / "tools/vm/pam-login-probe.sh").read_text(encoding="utf-8")
        self.assertIn("auth    required  pam_unix.so", pam)
        self.assertNotIn("pam_google_authenticator", pam)
        self.assertIn('"${bundle}/pam/vps-guard"', update)
        self.assertIn("/etc/pam.d/vps-guard", update)
        self.assertNotIn(".google_authenticator", probe)
        self.assertIn('read -r -s -p "PAM_TOTP:" token', probe)

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

    def test_certbot_hook_fails_closed_on_served_certificate_mismatch(self) -> None:
        hook = (self.root / "packaging/certbot/vps-guard-deploy-hook").read_text(
            encoding="utf-8"
        )
        site_hook = (self.root / "configs/certbot/g7devops-deploy-hook").read_text(
            encoding="utf-8"
        )
        self.assertIn('VPS_GUARD_TLS_SERVER_NAME is required', hook)
        self.assertIn('VPS_GUARD_TLS_ADDRESS is required', hook)
        self.assertIn("verify-served-certificate", hook)
        self.assertIn('--certificate "${cert}"', hook)
        self.assertIn('--key "${key}"', hook)
        self.assertIn("VPS_GUARD_TLS_SERVER_NAME=www.g7devops.com", site_hook)
        self.assertIn("VPS_GUARD_TLS_ADDRESS=127.0.0.1:443", site_hook)

    def test_systemd_verify_ignores_all_packaged_binary_absence_only(self) -> None:
        output = "\n".join(
            [
                "Command /usr/local/bin/vps-guard-control is not executable: No such file or directory",
                "Command /usr/local/bin/vps-guard-privileged is not executable: No such file or directory",
                "Command /usr/local/bin/vps-guard-edge is not executable: No such file or directory",
                "Unknown lvalue 'UnsafeSetting' in section 'Service'",
            ]
        )
        self.assertEqual(
            _remaining_systemd_verify_errors(output),
            ["Unknown lvalue 'UnsafeSetting' in section 'Service'"],
        )


if __name__ == "__main__":
    unittest.main()
