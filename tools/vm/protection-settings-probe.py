#!/usr/bin/env python3
"""UI-018 authenticated plan/apply, Edge read-back and restore VM probe."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 1_048_576
SETTING_NAMES = (
    "watch_strict_requests_per_minute",
    "local_strict_requests_per_minute",
    "local_upload_requests_per_minute",
    "emergency_strict_requests_per_minute",
    "emergency_upload_requests_per_minute",
)


class ProbeError(RuntimeError):
    """A bounded API or restoration invariant failed."""


@dataclass(frozen=True)
class Endpoint:
    """Validated loopback HTTP endpoint."""

    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "Endpoint":
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
    """In-memory break-glass session material that is never printed."""

    cookie: str
    csrf_token: str


class Api:
    """Small bounded JSON client for the loopback Control and Edge."""

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
        response, headers = self._control(
            "POST",
            "/api/v1/session",
            {"login_code": login_code},
            headers={"Origin": self.management_origin},
        )
        cookie = _session_cookie(headers.get("set-cookie", ""))
        csrf = response.get("csrf_token")
        if not isinstance(csrf, str) or not csrf:
            raise ProbeError("break-glass session CSRF token이 없습니다")
        return Session(cookie=cookie, csrf_token=csrf)

    def settings(self, session: Session) -> dict[str, Any]:
        response, _headers = self._control(
            "GET",
            "/api/v1/settings/protection",
            None,
            headers={"Cookie": session.cookie},
        )
        return response

    def plan(self, session: Session, settings: dict[str, int]) -> dict[str, Any]:
        response, _headers = self._control(
            "POST",
            "/api/v1/settings/protection/plan",
            {"settings": settings},
            headers=self._mutation_headers(session),
        )
        return response

    def apply(
        self,
        session: Session,
        settings: dict[str, int],
        plan: dict[str, Any],
        operation_id: str,
    ) -> dict[str, Any]:
        response, _headers = self._control(
            "POST",
            "/api/v1/settings/protection/apply",
            {
                "settings": settings,
                "current_fingerprint": _string(plan, "current_fingerprint"),
                "plan_hash": _string(plan, "plan_hash"),
            },
            headers={
                **self._mutation_headers(session),
                "Idempotency-Key": operation_id,
            },
        )
        return response

    def edge_samples(self) -> dict[str, int]:
        samples = {}
        for label, path in (
            ("normal", "/"),
            ("strict", "/bbs/login.php"),
            ("upload", "/data/file/__vpsguard_policy_probe__"),
        ):
            connection = http.client.HTTPConnection(self.edge.host, self.edge.port, timeout=3)
            try:
                connection.request(
                    "GET",
                    path,
                    headers={"Host": self.edge_host, "User-Agent": "VPSGuard-UI018-Probe/1"},
                )
                response = connection.getresponse()
                response.read(MAX_RESPONSE_BYTES)
            except OSError as error:
                raise ProbeError(f"Edge {label} probe 연결 실패: {error}") from error
            finally:
                connection.close()
            if not 100 <= response.status < 500:
                raise ProbeError(f"Edge {label} probe가 server error를 반환했습니다: {response.status}")
            samples[label] = response.status
        return samples

    def wait_for_readback(
        self,
        session: Session,
        policy_version: int,
        *,
        timeout_seconds: int,
    ) -> tuple[dict[str, Any], dict[str, int]]:
        deadline = time.monotonic() + timeout_seconds
        last: dict[str, Any] = {}
        samples: dict[str, int] = {}
        while time.monotonic() < deadline:
            samples = self.edge_samples()
            last = self.settings(session)
            if (
                last.get("policy_version") == policy_version
                and last.get("edge_observed_policy_version") == policy_version
                and last.get("edge_readback") == "observed"
            ):
                return last, samples
            time.sleep(0.5)
        raise ProbeError(
            "Edge policy version read-back 시간 초과: "
            f"expected={policy_version}, observed={last.get('edge_observed_policy_version')}"
        )

    def _mutation_headers(self, session: Session) -> dict[str, str]:
        return {
            "Cookie": session.cookie,
            "Origin": self.management_origin,
            "X-CSRF-Token": session.csrf_token,
        }

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
            raise ProbeError(f"Control API JSON 응답이 올바르지 않습니다: status={response.status}") from error
        if not 200 <= response.status < 300 or not isinstance(decoded, dict):
            code = decoded.get("error", {}).get("code") if isinstance(decoded, dict) else None
            raise ProbeError(f"Control API가 요청을 거부했습니다: status={response.status}, code={code}")
        return decoded, {name.lower(): value for name, value in response.getheaders()}


def candidate_settings(current: dict[str, Any]) -> dict[str, int]:
    """Produce one valid, reversible setting change without weakening later stages."""

    settings: dict[str, int] = {}
    for name in SETTING_NAMES:
        value = current.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 6_000:
            raise ProbeError(f"보호 설정값이 올바르지 않습니다: {name}")
        settings[name] = value
    _validate_order(settings)
    if settings["watch_strict_requests_per_minute"] < 6_000:
        settings["watch_strict_requests_per_minute"] += 1
    else:
        settings = {name: max(1, value - 1) for name, value in settings.items()}
    _validate_order(settings)
    return settings


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    """Apply one candidate, prove Edge read-back, then restore exact original settings."""

    control = Endpoint.parse(arguments.control_url)
    edge = Endpoint.parse(arguments.edge_url)
    origin = urlsplit(arguments.management_origin)
    if (
        origin.scheme != "https"
        or origin.username
        or origin.password
        or origin.path not in {"", "/"}
        or origin.query
        or origin.fragment
    ):
        raise ProbeError("management origin은 credential 없는 HTTPS origin이어야 합니다")
    if arguments.management_host != origin.netloc:
        raise ProbeError("management Host와 Origin authority가 일치하지 않습니다")
    socket_path = Path(arguments.admin_socket)
    if not socket_path.is_absolute():
        raise ProbeError("admin socket은 절대 경로여야 합니다")
    api = Api(
        control,
        edge,
        management_host=arguments.management_host,
        management_origin=arguments.management_origin,
        edge_host=arguments.edge_host,
    )
    login_code = _issue_login_code(socket_path)
    session = api.login(login_code)
    login_code = ""
    initial = api.settings(session)
    original = _settings(initial)
    candidate = candidate_settings(original)
    baseline_samples = api.edge_samples()
    candidate_applied = False
    candidate_version = 0
    candidate_samples: dict[str, int] = {}
    restored_samples: dict[str, int] = {}
    restoration_error: Exception | None = None
    try:
        plan = api.plan(session, candidate)
        applied = api.apply(session, candidate, plan, f"ui018-candidate-{uuid.uuid4()}")
        if applied.get("applied") is not True:
            raise ProbeError("후보 보호 설정이 실제 적용되지 않았습니다")
        candidate_applied = True
        candidate_version = _integer(applied, "policy_version")
        _observed, candidate_samples = api.wait_for_readback(
            session,
            candidate_version,
            timeout_seconds=arguments.readback_timeout_seconds,
        )
    finally:
        if candidate_applied:
            try:
                restore_plan = api.plan(session, original)
                restored = api.apply(
                    session,
                    original,
                    restore_plan,
                    f"ui018-restore-{uuid.uuid4()}",
                )
                restored_version = _integer(restored, "policy_version")
                restored_state, restored_samples = api.wait_for_readback(
                    session,
                    restored_version,
                    timeout_seconds=arguments.readback_timeout_seconds,
                )
                if _settings(restored_state) != original:
                    raise ProbeError("원래 보호 설정 read-back이 일치하지 않습니다")
            except Exception as error:
                restoration_error = error
    if restoration_error is not None:
        raise ProbeError(f"보호 설정 자동 복구 실패: {restoration_error}")
    final = api.settings(session)
    if _settings(final) != original:
        raise ProbeError("최종 보호 설정이 원래 값과 일치하지 않습니다")
    return {
        "schema_version": 1,
        "result": "PASS",
        "authentication_method": "break_glass",
        "initial_policy_version": _integer(initial, "policy_version"),
        "candidate_policy_version": candidate_version,
        "restored_policy_version": _integer(final, "policy_version"),
        "edge_readback": final.get("edge_readback"),
        "enforcement_active": final.get("enforcement_active"),
        "baseline_status": baseline_samples,
        "candidate_status": candidate_samples,
        "restored_status": restored_samples,
        "original_settings_restored": True,
        "stores_credentials": False,
        "stores_request_bodies": False,
    }


def _issue_login_code(path: Path) -> str:
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
        chunks = []
        total = 0
        while chunk := client.recv(4_096):
            total += len(chunk)
            if total > 8_192:
                raise ProbeError("admin socket 응답이 크기 제한을 초과했습니다")
            chunks.append(chunk)
    except OSError as error:
        raise ProbeError(f"admin socket 요청 실패: {error}") from error
    finally:
        client.close()
    try:
        response = json.loads(b"".join(chunks))
    except json.JSONDecodeError as error:
        raise ProbeError("admin socket JSON 응답이 올바르지 않습니다") from error
    code = response.get("login_code") if isinstance(response, dict) else None
    if (
        response.get("status") != "login_code"
        or not isinstance(code, str)
        or len(code) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in code)
    ):
        raise ProbeError("admin socket이 단회 로그인 코드를 발급하지 않았습니다")
    return code


def _session_cookie(value: str) -> str:
    cookie = value.split(";", maxsplit=1)[0].strip()
    if "=" not in cookie or len(cookie) > 4_096:
        raise ProbeError("session cookie 응답이 올바르지 않습니다")
    return cookie


def _settings(response: dict[str, Any]) -> dict[str, int]:
    raw = response.get("settings")
    if not isinstance(raw, dict):
        raise ProbeError("보호 설정 응답이 없습니다")
    settings = {name: _setting_integer(raw, name) for name in SETTING_NAMES}
    _validate_order(settings)
    return settings


def _validate_order(settings: dict[str, int]) -> None:
    if (
        settings["local_strict_requests_per_minute"]
        > settings["watch_strict_requests_per_minute"]
        or settings["emergency_strict_requests_per_minute"]
        > settings["local_strict_requests_per_minute"]
        or settings["local_upload_requests_per_minute"]
        > settings["local_strict_requests_per_minute"]
        or settings["emergency_upload_requests_per_minute"]
        > settings["local_upload_requests_per_minute"]
        or settings["emergency_upload_requests_per_minute"]
        > settings["emergency_strict_requests_per_minute"]
    ):
        raise ProbeError("보호 설정 단계 관계가 올바르지 않습니다")


def _setting_integer(value: dict[str, Any], name: str) -> int:
    raw = value.get(name)
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise ProbeError(f"보호 설정 응답값이 올바르지 않습니다: {name}")
    return raw


def _integer(value: dict[str, Any], name: str) -> int:
    raw = value.get(name)
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise ProbeError(f"응답 정수값이 올바르지 않습니다: {name}")
    return raw


def _string(value: dict[str, Any], name: str) -> str:
    raw = value.get(name)
    if not isinstance(raw, str) or not raw:
        raise ProbeError(f"응답 문자열이 올바르지 않습니다: {name}")
    return raw


def parser() -> argparse.ArgumentParser:
    """Return the strict standalone probe CLI parser."""

    value = argparse.ArgumentParser()
    value.add_argument("--control-url", required=True)
    value.add_argument("--edge-url", required=True)
    value.add_argument("--management-host", required=True)
    value.add_argument("--management-origin", required=True)
    value.add_argument("--edge-host", required=True)
    value.add_argument("--admin-socket", required=True)
    value.add_argument("--readback-timeout-seconds", type=int, default=15)
    return value


def main() -> int:
    """Run the probe without ever printing session material."""

    try:
        arguments = parser().parse_args()
        if not 3 <= arguments.readback_timeout_seconds <= 60:
            raise ProbeError("read-back timeout은 3..60초여야 합니다")
        print(json.dumps(run(arguments), ensure_ascii=False, separators=(",", ":")))
    except ProbeError as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "result": "FAIL",
                    "problem": str(error),
                    "impact": "후보 설정 적용을 중단하고 가능한 경우 원래 설정 복구를 시도했습니다.",
                    "next_action": "Control·Edge 상태와 정책 read-back을 확인하십시오.",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
