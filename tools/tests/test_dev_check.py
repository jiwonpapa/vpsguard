"""Developer-scoped verification plan contracts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.dev_check import DevCheckError, build_dev_check_plan


class DevCheckTests(unittest.TestCase):
    """Fast checks must stay explicit and bounded to a selected surface."""

    def test_rust_crate_plan_does_not_build_the_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/guard-edge").mkdir(parents=True)
            (root / "crates/guard-edge/Cargo.toml").write_text(
                '[package]\nname = "guard-edge"\n', encoding="utf-8"
            )
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/guard-edge"]\n', encoding="utf-8"
            )

            plan = build_dev_check_plan(root, "guard-edge")

            self.assertEqual(len(plan.commands), 3)
            self.assertEqual(plan.commands[0].argv, ("cargo", "fmt", "--all", "--", "--check"))
            for command in plan.commands[1:]:
                self.assertIn("-p", command.argv)
                self.assertIn("guard-edge", command.argv)
                self.assertNotIn("--workspace", command.argv)

    def test_python_and_web_scopes_use_their_native_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "web").mkdir()
            (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")

            python = build_dev_check_plan(root, "python")
            web = build_dev_check_plan(root, "web")

            self.assertEqual(len(python.commands), 2)
            self.assertEqual(python.commands[0].argv[0], "python3")
            self.assertEqual(web.commands[0].argv, ("bun", "run", "check"))
            self.assertEqual(web.commands[0].cwd, root.resolve() / "web")

    def test_unknown_scope_is_rejected_before_command_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/guard-edge").mkdir(parents=True)
            (root / "crates/guard-edge/Cargo.toml").write_text(
                '[package]\nname = "guard-edge"\n', encoding="utf-8"
            )
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/guard-edge"]\n', encoding="utf-8"
            )

            with self.assertRaises(DevCheckError) as raised:
                build_dev_check_plan(root, "guard-missing")

            self.assertEqual(raised.exception.code, "DEV_CHECK_SCOPE_INVALID")


if __name__ == "__main__":
    unittest.main()
