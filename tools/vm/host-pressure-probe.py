#!/usr/bin/env python3
"""DET-014 bounded CPU pressure, `/proc` comparison and recovery probe."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from host_pressure_support import (
    CPU_WORKER_COMMAND,
    Api,
    Endpoint,
    ProbeError,
    cpu_usage_percent,
    issue_login_code,
    memory_snapshot,
    read_guest,
    start_workers,
    stop_workers,
    summarize_timeline,
)

_TERMINATED = False


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    """Drive baseline, pressure and recovery while retaining no credential."""

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
        or arguments.management_host != origin.netloc
    ):
        raise ProbeError("management Host와 HTTPS Origin이 올바르지 않습니다")
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
    login_code = issue_login_code(socket_path)
    session = api.login(login_code)
    login_code = ""
    timeline: list[dict[str, Any]] = []
    started = time.monotonic()
    previous_stat = read_guest("/proc/stat")
    request_statuses: dict[str, int] = {}

    previous_stat = _baseline(
        api,
        session,
        timeline,
        previous_stat,
        started,
        arguments.sample_interval_ms,
        request_statuses,
    )
    workers = start_workers(arguments.cpu_workers)
    pressure_error: Exception | None = None
    try:
        previous_stat = _phase(
            api,
            session,
            timeline,
            previous_stat,
            started,
            phase="pressure",
            path="/bbs/search.php?stx=vpsguard-pressure",
            duration_seconds=arguments.pressure_seconds,
            sample_interval_ms=arguments.sample_interval_ms,
            request_interval_ms=arguments.request_interval_ms,
            request_statuses=request_statuses,
            stop_on_normal=False,
        )[0]
    except Exception as error:
        pressure_error = error
    finally:
        stop_workers(workers)
    previous_stat, recovered = _phase(
        api,
        session,
        timeline,
        previous_stat,
        started,
        phase="recovery",
        path="/",
        duration_seconds=arguments.recovery_timeout_seconds,
        sample_interval_ms=arguments.sample_interval_ms,
        request_interval_ms=arguments.request_interval_ms,
        request_statuses=request_statuses,
        stop_on_normal=True,
    )
    if pressure_error is not None:
        raise pressure_error
    if not recovered:
        raise ProbeError("recovery timeout 안에 NORMAL로 복귀하지 못했습니다")
    final_status = api.status(session)
    summary = summarize_timeline(
        timeline,
        provider_status=str(final_status.get("provider", "")),
    )
    return {
        "schema_version": 1,
        "result": "PASS",
        "authentication_method": "break_glass",
        "summary": summary,
        "request_status_counts": request_statuses,
        "timeline": timeline,
        "stores_credentials": False,
        "stores_response_bodies": False,
        "stores_request_bodies": False,
    }


def _baseline(
    api: Api,
    session: object,
    timeline: list[dict[str, Any]],
    previous_stat: str,
    started: float,
    sample_interval_ms: int,
    request_statuses: dict[str, int],
) -> str:
    deadline = time.monotonic() + 20
    consecutive_normal = 0
    while time.monotonic() < deadline:
        _require_running()
        _count_status(request_statuses, api.edge_request("/"))
        time.sleep(sample_interval_ms / 1_000)
        sample, previous_stat = _sample(
            api, session, "baseline", started, previous_stat
        )
        timeline.append(sample)
        consecutive_normal = consecutive_normal + 1 if sample["mode"] == "NORMAL" else 0
        if consecutive_normal >= 2:
            return previous_stat
    raise ProbeError("pressure 전 NORMAL baseline을 만들지 못했습니다")


def _phase(
    api: Api,
    session: object,
    timeline: list[dict[str, Any]],
    previous_stat: str,
    started: float,
    *,
    phase: str,
    path: str,
    duration_seconds: int,
    sample_interval_ms: int,
    request_interval_ms: int,
    request_statuses: dict[str, int],
    stop_on_normal: bool,
) -> tuple[str, bool]:
    phase_started = time.monotonic()
    next_request = phase_started
    next_sample = phase_started
    recovering_seen = False
    normal_samples = 0
    while time.monotonic() - phase_started < duration_seconds:
        _require_running()
        now = time.monotonic()
        if now >= next_request:
            _count_status(request_statuses, api.edge_request(path))
            next_request += request_interval_ms / 1_000
        if now >= next_sample:
            sample, previous_stat = _sample(
                api, session, phase, started, previous_stat
            )
            timeline.append(sample)
            recovering_seen = recovering_seen or sample["mode"] == "RECOVERING"
            normal_samples = normal_samples + 1 if sample["mode"] == "NORMAL" else 0
            if stop_on_normal and recovering_seen and normal_samples >= 2:
                return previous_stat, True
            next_sample += sample_interval_ms / 1_000
        time.sleep(0.05)
    return previous_stat, False


def _sample(
    api: Api,
    session: object,
    phase: str,
    started: float,
    previous_stat: str,
) -> tuple[dict[str, Any], str]:
    current_stat = read_guest("/proc/stat")
    direct_cpu = cpu_usage_percent(previous_stat, current_stat)
    direct_memory = memory_snapshot(read_guest("/proc/meminfo"))
    status = api.status(session)
    resources = api.resources(session)
    api_os = resources.get("os")
    if resources.get("state") != "live" or not isinstance(api_os, dict):
        raise ProbeError("Control OS collector가 live가 아닙니다")
    mode = status.get("mode")
    if not isinstance(mode, str):
        raise ProbeError("Control guard mode가 없습니다")
    api_cpu = api_os.get("cpu_usage_percent")
    if api_cpu is not None and not isinstance(api_cpu, int):
        raise ProbeError("Control CPU percent가 올바르지 않습니다")
    return (
        {
            "elapsed_ms": int((time.monotonic() - started) * 1_000),
            "phase": phase,
            "mode": mode,
            "provider": status.get("provider"),
            "direct_cpu_percent": direct_cpu,
            "api_cpu_percent": api_cpu,
            "direct_load_1m": float(read_guest("/proc/loadavg").split()[0]),
            "api_load_1m": api_os.get("load_1m"),
            "direct_memory_total_bytes": direct_memory["memory_total_bytes"],
            "direct_memory_available_bytes": direct_memory["memory_available_bytes"],
            "api_memory_total_bytes": api_os.get("memory_total_bytes"),
            "api_memory_available_bytes": api_os.get("memory_available_bytes"),
            "api_swap_total_bytes": api_os.get("swap_total_bytes"),
            "api_swap_free_bytes": api_os.get("swap_free_bytes"),
        },
        current_stat,
    )


def _count_status(counts: dict[str, int], status: int) -> None:
    key = str(status)
    counts[key] = counts.get(key, 0) + 1


def _require_running() -> None:
    if _TERMINATED:
        raise ProbeError("pressure probe가 종료 signal을 받았습니다")


def _signal_handler(_signum: int, _frame: object) -> None:
    global _TERMINATED
    _TERMINATED = True


def parser() -> argparse.ArgumentParser:
    """Return the strict standalone pressure probe parser."""

    value = argparse.ArgumentParser()
    value.add_argument("--control-url", required=True)
    value.add_argument("--edge-url", required=True)
    value.add_argument("--management-host", required=True)
    value.add_argument("--management-origin", required=True)
    value.add_argument("--edge-host", required=True)
    value.add_argument("--admin-socket", required=True)
    value.add_argument("--pressure-seconds", type=int, required=True)
    value.add_argument("--recovery-timeout-seconds", type=int, required=True)
    value.add_argument("--sample-interval-ms", type=int, required=True)
    value.add_argument("--request-interval-ms", type=int, required=True)
    value.add_argument("--cpu-workers", type=int, required=True)
    return value


def main() -> int:
    """Run the probe without printing session or response body material."""

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
    try:
        arguments = parser().parse_args()
        if (
            not 20 <= arguments.pressure_seconds <= 120
            or not 20 <= arguments.recovery_timeout_seconds <= 120
            or arguments.sample_interval_ms != 1_000
            or not 1_000 <= arguments.request_interval_ms <= 5_000
            or not 1 <= arguments.cpu_workers <= 64
        ):
            raise ProbeError("pressure 실행 bound가 올바르지 않습니다")
        print(json.dumps(run(arguments), ensure_ascii=False, separators=(",", ":")))
    except ProbeError as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "result": "FAIL",
                    "problem": str(error),
                    "impact": "CPU worker를 종료하고 가능한 경우 recovery request를 수행했습니다.",
                    "next_action": "Control state·resource와 guest worker process를 확인하십시오.",
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
