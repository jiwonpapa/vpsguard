"""Bounded libvirt QEMU guest-agent command execution over an SSH host."""

from __future__ import annotations

import base64
import json
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .runner import CommandRunner, CommandScope, CommandSpec


class GuestAgentError(HarnessError):
    """The host transport or guest command violated the QGA contract."""


@dataclass(frozen=True)
class GuestCommandResult:
    """One completed root guest-agent command with bounded output."""

    exit_code: int
    stdout: str
    stderr: str


class GuestAgent:
    """Execute argv-only commands through one libvirt domain's guest agent."""

    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        *,
        host_alias: str,
        domain: str,
    ) -> None:
        self._runner = runner
        self._root = root
        self._host_alias = _identifier(host_alias, "host alias")
        self._domain = _identifier(domain, "domain")

    def ping(self) -> None:
        """Require a responsive guest agent before any guest command."""

        response = self._agent_call({"execute": "guest-ping"}, timeout_seconds=10)
        if response.get("return") != {}:
            _raise("QGA_PING_FAILED", "guest agent ping 응답이 올바르지 않습니다.", repr(response))

    def execute(
        self,
        argv: tuple[str, ...],
        *,
        environment: tuple[str, ...] = (),
        timeout_seconds: int = 60,
        accepted_exit_codes: tuple[int, ...] = (0,),
    ) -> GuestCommandResult:
        """Execute an absolute guest path and poll its typed completion result."""

        if (
            not argv
            or not argv[0].startswith("/")
            or any(not value or any(control in value for control in "\x00\r\n") for value in argv)
        ):
            _raise("QGA_ARGV_INVALID", "guest command argv가 올바르지 않습니다.", repr(argv))
        if (
            any("=" not in value or any(control in value for control in "\x00\r\n") for value in environment)
            or not 1 <= timeout_seconds <= 600
            or not accepted_exit_codes
        ):
            _raise(
                "QGA_EXECUTION_BOUNDS_INVALID",
                "guest command 환경 또는 실행 제한이 올바르지 않습니다.",
                f"timeout={timeout_seconds}, environment_count={len(environment)}",
            )
        arguments: dict[str, object] = {
            "path": argv[0],
            "arg": list(argv[1:]),
            "capture-output": True,
        }
        if environment:
            arguments["env"] = list(environment)
        started = self._agent_call(
            {"execute": "guest-exec", "arguments": arguments},
            timeout_seconds=10,
        )
        try:
            process_id = int(started["return"]["pid"])
        except (KeyError, TypeError, ValueError) as error:
            _raise("QGA_EXEC_START_FAILED", "guest command PID를 받지 못했습니다.", str(error))
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status = self._agent_call(
                {
                    "execute": "guest-exec-status",
                    "arguments": {"pid": process_id},
                },
                timeout_seconds=10,
            )
            result = status.get("return")
            if isinstance(result, dict) and result.get("exited") is True:
                completed = GuestCommandResult(
                    exit_code=int(result.get("exitcode", -1)),
                    stdout=_decoded(result.get("out-data")),
                    stderr=_decoded(result.get("err-data")),
                )
                if completed.exit_code not in accepted_exit_codes:
                    _raise(
                        "QGA_GUEST_COMMAND_FAILED",
                        "guest command가 실패했습니다.",
                        completed.stderr.strip()
                        or completed.stdout.strip()
                        or f"exit={completed.exit_code}",
                    )
                return completed
            time.sleep(0.2)
        _raise(
            "QGA_GUEST_COMMAND_TIMEOUT",
            "guest command가 제한 시간 안에 끝나지 않았습니다.",
            f"timeout={timeout_seconds}s",
        )

    def _agent_call(self, payload: dict[str, object], *, timeout_seconds: int) -> dict[str, object]:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        remote = shlex.join(
            (
                "virsh",
                "-c",
                "qemu:///system",
                "qemu-agent-command",
                self._domain,
                encoded,
            )
        )
        result = self._runner.run(
            CommandSpec(
                label=f"qga {payload['execute']}",
                argv=("ssh", "-o", "BatchMode=yes", self._host_alias, remote),
                cwd=self._root,
                timeout_seconds=timeout_seconds,
                scope=CommandScope.TEST,
                max_output_bytes=1_048_576,
            )
        )
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            _raise("QGA_RESPONSE_INVALID", "guest agent JSON 응답이 올바르지 않습니다.", str(error))
        if not isinstance(response, dict) or "error" in response:
            _raise("QGA_RESPONSE_ERROR", "guest agent가 요청을 거부했습니다.", repr(response))
        return response


def _decoded(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        _raise("QGA_OUTPUT_INVALID", "guest agent 출력 encoding이 올바르지 않습니다.", str(error))
    if len(decoded) > 1_048_576:
        _raise("QGA_OUTPUT_TOO_LARGE", "guest agent 출력이 허용 크기를 초과했습니다.", str(len(decoded)))
    return decoded.decode("utf-8", errors="replace")


def _identifier(value: str, label: str) -> str:
    if (
        not value
        or len(value) > 128
        or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-" for character in value)
    ):
        _raise("QGA_IDENTIFIER_INVALID", f"{label} 형식이 올바르지 않습니다.", repr(value))
    return value


def _raise(code: str, problem: str, cause: str) -> None:
    raise GuestAgentError(
        code=code,
        problem=problem,
        cause=cause,
        impact="guest 명령과 이후 VM 변경을 중단했습니다.",
        next_action="libvirt domain, guest agent와 bounded argv를 확인하십시오.",
    )
