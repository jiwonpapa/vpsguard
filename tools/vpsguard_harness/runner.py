"""Bounded argv-only command execution for local and CI harnesses."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from .errors import HarnessError


class CommandScope(StrEnum):
    """Allowed non-production execution purposes for the Python harness."""

    GOVERNANCE = "governance"
    TEST = "test"
    BUILD = "build"
    COMPATIBILITY = "compatibility"


@dataclass(frozen=True)
class CommandSpec:
    """One bounded subprocess invocation without shell interpretation."""

    label: str
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float
    scope: CommandScope
    stdout_path: Path | None = None
    accepted_exit_codes: tuple[int, ...] = (0,)
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if isinstance(self.argv, str) or not isinstance(self.argv, tuple):
            raise TypeError("argv must be a tuple of strings")
        if not self.argv or any(not isinstance(argument, str) for argument in self.argv):
            raise TypeError("argv must contain at least one string")
        if any("\x00" in argument or "\n" in argument or "\r" in argument for argument in self.argv):
            raise ValueError("argv must not contain control separators")
        if not self.label or len(self.label) > 96:
            raise ValueError("label must contain 1..=96 characters")
        if not 0 < self.timeout_seconds <= 3_600:
            raise ValueError("timeout_seconds must be within 0..=3600")
        if not self.accepted_exit_codes:
            raise ValueError("at least one accepted exit code is required")
        if not 64 <= self.max_output_bytes <= 16_777_216:
            raise ValueError("max_output_bytes must be within 64..=16777216")
        if not self.cwd.is_absolute() or not self.cwd.is_dir():
            raise ValueError("cwd must be an existing absolute directory")
        if self.stdout_path is not None:
            destination = self.stdout_path.resolve(strict=False)
            if not destination.is_relative_to(self.cwd.resolve()):
                raise ValueError("stdout_path must remain below cwd")


@dataclass(frozen=True)
class CommandResult:
    """Redacted, bounded result of one command invocation."""

    label: str
    scope: CommandScope
    exit_code: int
    elapsed_ms: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class BackgroundCommandSpec:
    """One long-running argv process with bounded startup confirmation."""

    label: str
    argv: tuple[str, ...]
    cwd: Path
    startup_seconds: float
    scope: CommandScope
    max_output_bytes: int = 65_536

    def __post_init__(self) -> None:
        if isinstance(self.argv, str) or not isinstance(self.argv, tuple):
            raise TypeError("argv must be a tuple of strings")
        if not self.argv or any(not isinstance(argument, str) for argument in self.argv):
            raise TypeError("argv must contain at least one string")
        if any("\x00" in argument or "\n" in argument or "\r" in argument for argument in self.argv):
            raise ValueError("argv must not contain control separators")
        if not self.label or len(self.label) > 96:
            raise ValueError("label must contain 1..=96 characters")
        if not 0 < self.startup_seconds <= 30:
            raise ValueError("startup_seconds must be within 0..=30")
        if not 64 <= self.max_output_bytes <= 16_777_216:
            raise ValueError("max_output_bytes must be within 64..=16777216")
        if not self.cwd.is_absolute() or not self.cwd.is_dir():
            raise ValueError("cwd must be an existing absolute directory")


class HarnessCommandError(HarnessError):
    """A command failed, timed out or could not be started."""


@dataclass
class _BoundedCapture:
    data: bytearray
    truncated: bool = False

    def append(self, chunk: bytes, limit: int) -> None:
        remaining = limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > remaining:
            self.truncated = True


class RunningCommand:
    """Owned background process that terminates its complete process group."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        output: BinaryIO,
    ) -> None:
        self._process = process
        self._output = output
        self._closed = False

    @property
    def pid(self) -> int:
        """Return the directly owned process PID."""

        return self._process.pid

    @property
    def is_running(self) -> bool:
        """Return whether the owned process has not exited."""

        return not self._closed and self._process.poll() is None

    def stop(self, *, timeout_seconds: float = 5) -> None:
        """Terminate and reap the process group exactly once."""

        if self._closed:
            return
        if self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self._process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self._process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self._process.wait(timeout=timeout_seconds)
        self._output.close()
        self._closed = True


class CommandRunner:
    """Execute fixed argv with timeout, redaction and atomic evidence writes."""

    def __init__(self, *, secrets: tuple[str, ...] = ()) -> None:
        self._secrets = tuple(secret for secret in secrets if secret)

    def run(self, spec: CommandSpec) -> CommandResult:
        """Run a command and return redacted output or a structured failure."""

        started = time.monotonic_ns()
        try:
            process = subprocess.Popen(
                list(spec.argv),
                cwd=spec.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            raise HarnessCommandError(
                code="HARNESS_COMMAND_START_FAILED",
                problem=f"{spec.label} 명령을 시작하지 못했습니다.",
                cause=self._redact(str(error)),
                impact="현재 하네스 단계와 이후 단계는 실행하지 않았습니다.",
                next_action="실행 파일과 작업 directory를 확인하십시오.",
            ) from error

        stdout_capture = _BoundedCapture(bytearray())
        stderr_capture = _BoundedCapture(bytearray())
        stdout_thread = threading.Thread(
            target=self._drain,
            args=(process.stdout, stdout_capture, spec.max_output_bytes),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._drain,
            args=(process.stderr, stderr_capture, spec.max_output_bytes),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            exit_code = process.wait(timeout=spec.timeout_seconds)
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            self._close_streams(process)
            cause = self._redact(
                self._decode_capture(stderr_capture) or self._decode_capture(stdout_capture)
            )
            raise HarnessCommandError(
                code="HARNESS_COMMAND_TIMEOUT",
                problem=f"{spec.label} 명령이 제한 시간 안에 끝나지 않았습니다.",
                cause=cause or f"timeout={spec.timeout_seconds:g}s",
                impact="현재 하네스 단계와 이후 단계는 실행하지 않았습니다.",
                next_action="명령의 대상 상태와 timeout 근거를 확인한 뒤 다시 실행하십시오.",
            ) from error
        stdout_thread.join()
        stderr_thread.join()
        self._close_streams(process)

        stdout = self._redact(self._decode_capture(stdout_capture))
        stderr = self._redact(self._decode_capture(stderr_capture))
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        if exit_code not in spec.accepted_exit_codes:
            cause = stderr.strip() or stdout.strip() or f"exit={exit_code}"
            raise HarnessCommandError(
                code="HARNESS_COMMAND_FAILED",
                problem=f"{spec.label} 명령이 실패했습니다.",
                cause=cause,
                impact="현재 하네스 단계와 이후 단계는 실행하지 않았습니다.",
                next_action="마스킹된 명령 출력을 확인하고 원인을 해결한 뒤 다시 실행하십시오.",
            )
        if spec.stdout_path is not None:
            self._atomic_write(spec.stdout_path, stdout)
        return CommandResult(
            label=spec.label,
            scope=spec.scope,
            exit_code=exit_code,
            elapsed_ms=elapsed_ms,
            stdout=stdout,
            stderr=stderr,
        )

    def start(self, spec: BackgroundCommandSpec) -> RunningCommand:
        """Start one owned background process and reject early exit."""

        output = tempfile.TemporaryFile(mode="w+b")
        try:
            process = subprocess.Popen(
                list(spec.argv),
                cwd=spec.cwd,
                stdout=output,
                stderr=output,
                start_new_session=True,
            )
        except OSError as error:
            output.close()
            raise HarnessCommandError(
                code="HARNESS_BACKGROUND_START_FAILED",
                problem=f"{spec.label} background 명령을 시작하지 못했습니다.",
                cause=self._redact(str(error)),
                impact="background 자원을 만들지 않았고 현재 단계를 중단했습니다.",
                next_action="실행 파일, argv와 작업 directory를 확인하십시오.",
            ) from error
        deadline = time.monotonic() + spec.startup_seconds
        while time.monotonic() < deadline:
            exit_code = process.poll()
            if exit_code is not None:
                output.seek(0)
                captured = output.read(spec.max_output_bytes + 1)
                output.close()
                text = captured[: spec.max_output_bytes].decode(
                    encoding="utf-8",
                    errors="replace",
                )
                if len(captured) > spec.max_output_bytes:
                    text += "\n<output truncated>"
                raise HarnessCommandError(
                    code="HARNESS_BACKGROUND_EXITED",
                    problem=f"{spec.label} background 명령이 준비 전에 종료됐습니다.",
                    cause=self._redact(text.strip()) or f"exit={exit_code}",
                    impact="background 자원이 준비되지 않아 현재 단계를 중단했습니다.",
                    next_action="마스킹된 시작 출력을 확인하고 원인을 해결하십시오.",
                )
            time.sleep(0.05)
        return RunningCommand(process, output)

    def _redact(self, value: str) -> str:
        redacted = value
        for secret in self._secrets:
            redacted = redacted.replace(secret, "<redacted>")
        return redacted

    @staticmethod
    def _drain(
        stream: object,
        capture: _BoundedCapture,
        limit: int,
    ) -> None:
        if stream is None or not hasattr(stream, "read"):
            return
        while chunk := stream.read(65_536):
            capture.append(chunk, limit)

    @staticmethod
    def _decode_capture(capture: _BoundedCapture) -> str:
        text = capture.data.decode(encoding="utf-8", errors="replace")
        return text + ("\n<output truncated>" if capture.truncated else "")

    @staticmethod
    def _close_streams(process: subprocess.Popen[bytes]) -> None:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
