"""Release lifecycle fixture boundary regression tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.runner import (
    CommandRunner,
    CommandScope,
    CommandSpec,
    HarnessCommandError,
)


class ReleaseLifecycleBoundaryTests(unittest.TestCase):
    """Fixture root support must never become an unconfirmed mutation escape."""

    repository = Path(__file__).resolve().parents[2]

    def test_fixture_root_requires_the_exact_isolation_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for script in ("update-release.sh", "uninstall.sh"):
                with self.subTest(script=script):
                    with self.assertRaises(HarnessCommandError) as raised:
                        CommandRunner().run(
                            CommandSpec(
                                label=f"reject unconfirmed {script}",
                                argv=(
                                    "env",
                                    f"VPS_GUARD_TEST_ROOT={directory}",
                                    "bash",
                                    str(self.repository / "scripts" / script),
                                    "--plan",
                                ),
                                cwd=self.repository,
                                timeout_seconds=5,
                                scope=CommandScope.TEST,
                            )
                        )
                    self.assertIn("invalid isolated fixture root", raised.exception.cause)

    def test_fixture_root_never_accepts_the_real_root(self) -> None:
        with self.assertRaises(HarnessCommandError) as raised:
            CommandRunner().run(
                CommandSpec(
                    label="reject production root fixture",
                    argv=(
                        "env",
                        "VPS_GUARD_TEST_ROOT=/",
                        "VPS_GUARD_FIXTURE_CONFIRM=isolated-root",
                        "bash",
                        str(self.repository / "scripts/update-release.sh"),
                        "--plan",
                    ),
                    cwd=self.repository,
                    timeout_seconds=5,
                    scope=CommandScope.TEST,
                )
            )
        self.assertIn("invalid isolated fixture root", raised.exception.cause)


if __name__ == "__main__":
    unittest.main()
