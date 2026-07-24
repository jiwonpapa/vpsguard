"""QEMU guest-agent transport contract tests."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.qga import GuestAgent, GuestAgentError
from tools.vpsguard_harness.runner import CommandResult, CommandScope


class _Runner:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self.responses = responses
        self.commands = []

    def run(self, spec: object) -> CommandResult:
        self.commands.append(spec)
        response = self.responses.pop(0)
        return CommandResult(
            label="fixture",
            scope=CommandScope.TEST,
            exit_code=0,
            elapsed_ms=1,
            stdout=json.dumps(response),
            stderr="",
        )


class GuestAgentTest(unittest.TestCase):
    """Keep QGA commands argv-only, bounded and status checked."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_guest_exec_uses_compact_quoted_json_and_decodes_output(self) -> None:
        runner = _Runner(
            [
                {"return": {"pid": 41}},
                {
                    "return": {
                        "exited": True,
                        "exitcode": 0,
                        "out-data": base64.b64encode(b"active\n").decode(),
                    }
                },
            ]
        )
        guest = GuestAgent(runner, self.root, host_alias="gnuboard7", domain="gnuboard5")
        result = guest.execute(
            ("/bin/systemctl", "is-active", "vps-guard-edge"),
            environment=("LANG=C",),
        )
        self.assertEqual(result.stdout, "active\n")
        command = runner.commands[0]
        self.assertEqual(command.argv[:4], ("ssh", "-o", "BatchMode=yes", "gnuboard7"))
        self.assertIn("qemu-agent-command", command.argv[4])
        self.assertIn("guest-exec", command.argv[4])
        self.assertNotIn("\n", command.argv[4])

    def test_nonzero_guest_exit_and_unsafe_argv_fail_closed(self) -> None:
        runner = _Runner(
            [
                {"return": {"pid": 42}},
                {
                    "return": {
                        "exited": True,
                        "exitcode": 1,
                        "err-data": base64.b64encode(b"failed\n").decode(),
                    }
                },
            ]
        )
        guest = GuestAgent(runner, self.root, host_alias="gnuboard7", domain="gnuboard5")
        with self.assertRaises(GuestAgentError):
            guest.execute(("/bin/false",))
        with self.assertRaises(GuestAgentError):
            guest.execute(("relative", "argument"))

    def test_identifier_and_ping_contracts_are_strict(self) -> None:
        with self.assertRaises(GuestAgentError):
            GuestAgent(_Runner([]), self.root, host_alias="bad alias", domain="gnuboard5")
        runner = _Runner([{"return": {}}])
        GuestAgent(runner, self.root, host_alias="gnuboard7", domain="gnuboard5").ping()
        self.assertIn("guest-ping", runner.commands[0].argv[4])


if __name__ == "__main__":
    unittest.main()
