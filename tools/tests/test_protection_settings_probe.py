"""UI-018 standalone VM probe input and restoration helper tests."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def _load() -> object:
    path = Path(__file__).resolve().parents[1] / "vm/protection-settings-probe.py"
    spec = importlib.util.spec_from_file_location("protection_settings_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("probe module loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


probe = _load()


class ProtectionSettingsProbeTest(unittest.TestCase):
    """Keep the VM probe loopback-only, reversible and secret-free."""

    def settings(self, **changes: int) -> dict[str, int]:
        values = {
            "watch_strict_requests_per_minute": 120,
            "local_strict_requests_per_minute": 30,
            "local_upload_requests_per_minute": 15,
            "emergency_strict_requests_per_minute": 10,
            "emergency_upload_requests_per_minute": 5,
        }
        values.update(changes)
        return values

    def test_candidate_changes_only_watch_when_headroom_exists(self) -> None:
        current = self.settings()
        candidate = probe.candidate_settings(current)
        self.assertEqual(candidate["watch_strict_requests_per_minute"], 121)
        self.assertEqual(
            {name: value for name, value in candidate.items() if name != "watch_strict_requests_per_minute"},
            {name: value for name, value in current.items() if name != "watch_strict_requests_per_minute"},
        )
        self.assertEqual(current["watch_strict_requests_per_minute"], 120)

    def test_maximum_candidate_remains_monotonic_and_invalid_order_fails(self) -> None:
        candidate = probe.candidate_settings(
            self.settings(
                watch_strict_requests_per_minute=6_000,
                local_strict_requests_per_minute=6_000,
                local_upload_requests_per_minute=6_000,
                emergency_strict_requests_per_minute=6_000,
                emergency_upload_requests_per_minute=6_000,
            )
        )
        self.assertEqual(set(candidate.values()), {5_999})
        with self.assertRaises(probe.ProbeError):
            probe.candidate_settings(
                self.settings(local_strict_requests_per_minute=121)
            )

    def test_endpoint_and_cookie_parsing_fail_closed(self) -> None:
        self.assertEqual(probe.Endpoint.parse("http://127.0.0.1:7727").port, 7727)
        with self.assertRaises(probe.ProbeError):
            probe.Endpoint.parse("https://127.0.0.1:7727")
        with self.assertRaises(probe.ProbeError):
            probe.Endpoint.parse("http://192.168.0.143:7727")
        self.assertEqual(
            probe._session_cookie("vpsguard_session=abc; Secure; HttpOnly"),
            "vpsguard_session=abc",
        )
        with self.assertRaises(probe.ProbeError):
            probe._session_cookie("invalid")

    def test_release_bundle_packages_the_same_probe(self) -> None:
        root = Path(__file__).resolve().parents[2]
        release_script = (root / "scripts/build-release.sh").read_text(encoding="utf-8")
        self.assertIn(
            'install -m 0755 tools/vm/protection-settings-probe.py "${bundle}/scripts/"',
            release_script,
        )


if __name__ == "__main__":
    unittest.main()
