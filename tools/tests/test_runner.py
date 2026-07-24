"""Python harness command runner contracts."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.runner import (
    BackgroundCommandSpec,
    CommandRunner,
    CommandScope,
    CommandSpec,
    HarnessCommandError,
)


class CommandRunnerTests(unittest.TestCase):
    """Bounded argv execution and redaction must remain deterministic."""

    def test_runs_argv_without_a_shell_and_atomically_writes_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence" / "result.txt"
            result = CommandRunner().run(
                CommandSpec(
                    label="fixture",
                    argv=(sys.executable, "-c", "print('fixture-pass')"),
                    cwd=root,
                    timeout_seconds=2,
                    scope=CommandScope.TEST,
                    stdout_path=evidence,
                )
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "fixture-pass\n")
            self.assertEqual(evidence.read_text(encoding="utf-8"), "fixture-pass\n")

    def test_rejects_string_commands(self) -> None:
        with self.assertRaises(TypeError):
            CommandSpec(  # type: ignore[arg-type]
                label="unsafe",
                argv="echo unsafe",
                cwd=Path.cwd(),
                timeout_seconds=1,
                scope=CommandScope.GOVERNANCE,
            )

    def test_failure_redacts_secret_and_exposes_structured_remediation(self) -> None:
        secret = "fixture-secret-token"
        with self.assertRaises(HarnessCommandError) as raised:
            CommandRunner(secrets=(secret,)).run(
                CommandSpec(
                    label="failing-fixture",
                    argv=(
                        sys.executable,
                        "-c",
                        f"import sys; print('{secret}', file=sys.stderr); raise SystemExit(7)",
                    ),
                    cwd=Path.cwd(),
                    timeout_seconds=2,
                    scope=CommandScope.TEST,
                )
            )

        error = raised.exception
        self.assertEqual(error.code, "HARNESS_COMMAND_FAILED")
        self.assertNotIn(secret, str(error))
        self.assertIn("<redacted>", error.cause)
        self.assertTrue(error.problem)
        self.assertTrue(error.impact)
        self.assertTrue(error.next_action)

    def test_caps_captured_output_while_draining_the_child_process(self) -> None:
        result = CommandRunner().run(
            CommandSpec(
                label="bounded-output",
                argv=(sys.executable, "-c", "print('x' * 4096)"),
                cwd=Path.cwd(),
                timeout_seconds=2,
                scope=CommandScope.TEST,
                max_output_bytes=64,
            )
        )

        self.assertLess(len(result.stdout), 128)
        self.assertIn("<output truncated>", result.stdout)

    def test_timeout_terminates_the_process_group(self) -> None:
        with self.assertRaises(HarnessCommandError) as raised:
            CommandRunner().run(
                CommandSpec(
                    label="timeout-fixture",
                    argv=(sys.executable, "-c", "import time; time.sleep(2)"),
                    cwd=Path.cwd(),
                    timeout_seconds=0.05,
                    scope=CommandScope.TEST,
                )
            )

        self.assertEqual(raised.exception.code, "HARNESS_COMMAND_TIMEOUT")

    def test_background_process_is_owned_terminated_and_reaped(self) -> None:
        command = CommandRunner().start(
            BackgroundCommandSpec(
                label="background-fixture",
                argv=(
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                ),
                cwd=Path.cwd(),
                startup_seconds=0.1,
                scope=CommandScope.TEST,
            )
        )
        self.assertTrue(command.is_running)
        self.assertGreater(command.pid, 1)
        command.stop()
        self.assertFalse(command.is_running)
        command.stop()

    def test_background_early_exit_is_structured_and_redacted(self) -> None:
        secret = "background-fixture-secret"
        with self.assertRaises(HarnessCommandError) as raised:
            CommandRunner(secrets=(secret,)).start(
                BackgroundCommandSpec(
                    label="background-failure",
                    argv=(
                        sys.executable,
                        "-c",
                        f"import sys; print('{secret}'); raise SystemExit(9)",
                    ),
                    cwd=Path.cwd(),
                    startup_seconds=0.2,
                    scope=CommandScope.TEST,
                )
            )
        self.assertEqual(raised.exception.code, "HARNESS_BACKGROUND_EXITED")
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
