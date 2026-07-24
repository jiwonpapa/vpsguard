"""Shared bounded API, `/proc` and CPU-worker helpers for DET-014 proof."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 1_048_576
CPU_WORKER_COMMAND = ("/usr/bin/sha256sum", "/dev/zero")


class ProbeError(RuntimeError):
    """A bounded pressure, API or recovery invariant failed."""


@dataclass(frozen=True)
class Endpoint:
    """Validated loopback HTTP endpoint."""

    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "Endpoint":
        """Parse one credential-free loopback HTTP endpoint."""

        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.hostname is None
        ):
            raise ProbeError(f"loopback HTTP endpoint가 올바르지 않습니다: {value}")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ProbeError(f"endpoint IP가 올바르지 않습니다: {error}") from error
        if not address.is_loopback:
            raise ProbeError(f"loopback 밖 endpoint는 허용하지 않습니다: {address}")
        return cls(host=str(address), port=parsed.port or 80)


@dataclass(frozen=True)
class Session:
    """In-memory session material that is never printed."""

    cookie: str


class Api:
    """Bounded authenticated Control reads and body-discarding Edge requests."""

    def __init__(
        self,
        control: Endpoint,
        edge: Endpoint,
        *,
        management_host: str,
        management_origin: str,
        edge_host: str,
    ) -> None:
        self.control = control
        self.edge = edge
        self.management_host = management_host
        self.management_origin = management_origin
        self.edge_host = edge_host

    def login(self, login_code: str) -> Session:
        """Exchange one local code without retaining it."""

        _response, headers = self._control(
            "POST",
            "/api/v1/session",
            {"login_code": login_code},
            headers={"Origin": self.management_origin},
        )
        return Session(cookie=session_cookie(headers.get("set-cookie", "")))

    def status(self, session: Session) -> dict[str, Any]:
        """Read the current typed guard status."""

        response, _headers = self._control(
            "GET",
            "/api/v1/status",
            None,
            headers={"Cookie": session.cookie},
        )
        return response

    def resources(self, session: Session) -> dict[str, Any]:
        """Read the current OS collector snapshot."""

        response, _headers = self._control(
            "GET",
            "/api/v1/resources",
            None,
            headers={"Cookie": session.cookie},
        )
        return response

    def edge_request(self, path: str) -> int:
        """Send one fixed body-free request through Edge and discard its body."""

        if not path.startswith("/") or any(value in path for value in ("\r", "\n")):
            raise ProbeError("Edge path가 올바르지 않습니다")
        connection = http.client.HTTPConnection(self.edge.host, self.edge.port, timeout=5)
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": self.edge_host,
                    "User-Agent": "VPSGuard-DET014-Probe/1",
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
        except OSError as error:
            raise ProbeError(f"Edge pressure request 연결 실패: {error}") from error
        finally:
            connection.close()
        if len(body) > MAX_RESPONSE_BYTES or not 100 <= response.status < 500:
            raise ProbeError(f"Edge pressure request 응답이 올바르지 않습니다: {response.status}")
        return response.status

    def _control(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        *,
        headers: dict[str, str],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request_headers = {"Host": self.management_host, **headers}
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(self.control.host, self.control.port, timeout=5)
        try:
            connection.request(method, path, body=encoded, headers=request_headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
        except OSError as error:
            raise ProbeError(f"Control API 연결 실패: {error}") from error
        finally:
            connection.close()
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ProbeError("Control API 응답이 크기 제한을 초과했습니다")
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as error:
            raise ProbeError(f"Control API JSON 오류: status={response.status}") from error
        if not 200 <= response.status < 300 or not isinstance(decoded, dict):
            code = decoded.get("error", {}).get("code") if isinstance(decoded, dict) else None
            raise ProbeError(f"Control API 거부: status={response.status}, code={code}")
        return decoded, {name.lower(): value for name, value in response.getheaders()}


def cpu_usage_percent(previous: str, current: str) -> int | None:
    """Calculate Linux aggregate CPU usage from two `/proc/stat` samples."""

    before = _cpu_times(previous)
    after = _cpu_times(current)
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]
    if total_delta <= 0 or idle_delta < 0:
        return None
    return min(100, max(0, (total_delta - idle_delta) * 100 // total_delta))


def memory_snapshot(raw: str) -> dict[str, int]:
    """Parse the bounded `/proc/meminfo` fields used by the Control API."""

    values: dict[str, int] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, content = line.split(":", maxsplit=1)
        if name not in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            continue
        fields = content.split()
        if not fields or not fields[0].isdigit():
            raise ProbeError(f"/proc/meminfo 값이 올바르지 않습니다: {name}")
        values[name] = int(fields[0]) * 1024
    if set(values) != {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
        raise ProbeError("/proc/meminfo 필수 field가 없습니다")
    return {
        "memory_total_bytes": values["MemTotal"],
        "memory_available_bytes": values["MemAvailable"],
        "swap_total_bytes": values["SwapTotal"],
        "swap_free_bytes": values["SwapFree"],
    }


def summarize_timeline(
    timeline: list[dict[str, Any]],
    *,
    provider_status: str,
) -> dict[str, Any]:
    """Require pressure alignment, LOCAL_GUARD and deterministic NORMAL recovery."""

    if not timeline:
        raise ProbeError("pressure timeline이 비어 있습니다")
    modes = [sample.get("mode") for sample in timeline]
    try:
        baseline_normal = modes.index("NORMAL")
        watch = modes.index("WATCH", baseline_normal + 1)
        local = modes.index("LOCAL_GUARD", watch + 1)
        recovering = modes.index("RECOVERING", local + 1)
        recovered = modes.index("NORMAL", recovering + 1)
    except ValueError as error:
        raise ProbeError(f"필수 상태 전이 timeline이 없습니다: {modes}") from error
    aligned = [
        sample
        for sample in timeline
        if sample.get("phase") == "pressure"
        and isinstance(sample.get("direct_cpu_percent"), int)
        and isinstance(sample.get("api_cpu_percent"), int)
        and sample["direct_cpu_percent"] >= 85
        and sample["api_cpu_percent"] >= 85
    ]
    if not aligned:
        raise ProbeError("직접 `/proc`와 Control CPU pressure가 함께 관측되지 않았습니다")
    if not any(
        sample.get("mode") == "LOCAL_GUARD"
        and sample.get("direct_cpu_percent", 0) >= 85
        and sample.get("api_cpu_percent", 0) >= 85
        for sample in timeline
    ):
        raise ProbeError("실제 CPU pressure와 LOCAL_GUARD가 같은 sample에 없습니다")
    cpu_deltas = [
        abs(sample["direct_cpu_percent"] - sample["api_cpu_percent"])
        for sample in aligned
    ]
    max_delta = max(cpu_deltas, default=101)
    if max_delta > 25:
        raise ProbeError(f"`/proc`와 Control CPU 차이가 허용 범위를 넘었습니다: {max_delta}")
    totals = [
        sample["direct_memory_total_bytes"]
        for sample in timeline
        if isinstance(sample.get("direct_memory_total_bytes"), int)
    ]
    if not totals or not all(1_610_612_736 <= value <= 2_147_483_648 for value in totals):
        raise ProbeError("guest memory가 2GB 실행 범위를 벗어났습니다")
    memory_deltas = [
        abs(sample["direct_memory_total_bytes"] - sample["api_memory_total_bytes"])
        for sample in timeline
        if isinstance(sample.get("direct_memory_total_bytes"), int)
        and isinstance(sample.get("api_memory_total_bytes"), int)
    ]
    max_memory_delta = max(memory_deltas, default=2_147_483_649)
    if max_memory_delta > 4_096:
        raise ProbeError(
            f"`/proc`와 Control memory total이 일치하지 않습니다: {max_memory_delta}"
        )
    transitions = []
    for mode in modes:
        if not transitions or transitions[-1] != mode:
            transitions.append(mode)
    return {
        "samples": len(timeline),
        "mode_transitions": transitions,
        "local_guard_observed": local > watch,
        "recovering_observed": recovering > local,
        "normal_recovered": recovered > recovering,
        "aligned_pressure_samples": len(aligned),
        "max_cpu_alignment_delta": max_delta,
        "max_memory_alignment_bytes": max_memory_delta,
        "max_direct_cpu_percent": max(
            sample.get("direct_cpu_percent") or 0 for sample in timeline
        ),
        "max_api_cpu_percent": max(
            sample.get("api_cpu_percent") or 0 for sample in timeline
        ),
        "provider_status": provider_status,
        "provider_unavailable_kept_local": (
            provider_status == "unavailable" and "EMERGENCY_PROXY" not in modes
        ),
    }


def issue_login_code(path: Path) -> str:
    """Issue one root-local login code without printing it."""

    request = json.dumps(
        {
            "schema_version": 1,
            "command": {"kind": "issue_login_code", "ttl_seconds": 300},
        },
        separators=(",", ":"),
    ).encode() + b"\n"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(str(path))
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := client.recv(4_096):
            response += chunk
            if len(response) > 8_192:
                raise ProbeError("admin socket 응답이 크기 제한을 초과했습니다")
    except OSError as error:
        raise ProbeError(f"admin socket 요청 실패: {error}") from error
    finally:
        client.close()
    try:
        decoded = json.loads(response)
    except json.JSONDecodeError as error:
        raise ProbeError("admin socket JSON 응답이 올바르지 않습니다") from error
    code = decoded.get("login_code") if isinstance(decoded, dict) else None
    if (
        decoded.get("status") != "login_code"
        or not isinstance(code, str)
        or len(code) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in code)
    ):
        raise ProbeError("admin socket이 단회 로그인 코드를 발급하지 않았습니다")
    return code


def start_workers(count: int) -> list[subprocess.Popen[bytes]]:
    """Start a fixed number of body-free CPU workers."""

    if not Path(CPU_WORKER_COMMAND[0]).is_file():
        raise ProbeError("고정 CPU worker executable이 없습니다")
    return [
        subprocess.Popen(
            CPU_WORKER_COMMAND,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _worker in range(count)
    ]


def stop_workers(workers: list[subprocess.Popen[bytes]]) -> None:
    """Terminate and reap every owned CPU worker."""

    for worker in workers:
        if worker.poll() is None:
            worker.terminate()
    deadline = time.monotonic() + 5
    for worker in workers:
        try:
            worker.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=2)


def read_guest(path: str) -> str:
    """Read one fixed guest procfs path."""

    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise ProbeError(f"guest read 실패: path={path}") from error


def session_cookie(value: str) -> str:
    """Extract one bounded session cookie from Set-Cookie."""

    cookie = value.split(";", maxsplit=1)[0].strip()
    if "=" not in cookie or len(cookie) > 4_096:
        raise ProbeError("session cookie 응답이 올바르지 않습니다")
    return cookie


def _cpu_times(raw: str) -> tuple[int, int]:
    line = next((value for value in raw.splitlines() if value.startswith("cpu ")), "")
    fields = line.split()[1:9]
    if len(fields) < 4 or any(not value.isdigit() for value in fields):
        raise ProbeError("/proc/stat aggregate CPU가 올바르지 않습니다")
    values = [int(value) for value in fields]
    return sum(values), values[3] + (values[4] if len(values) > 4 else 0)
