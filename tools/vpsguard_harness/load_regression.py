"""Same-host direct-origin versus guard-edge latency and throughput release gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import HarnessError
from .runner import (
    BackgroundCommandSpec,
    CommandRunner,
    CommandScope,
    CommandSpec,
    RunningCommand,
)

MAX_P95_OVERHEAD_MS = 2.0
MAX_THROUGHPUT_REDUCTION_PERCENT = 10.0
DEFAULT_VUS = "50"
DEFAULT_DURATION = "15s"


@dataclass(frozen=True)
class LoadMetrics:
    """Reviewed k6 metrics used by the release decision."""

    p95_ms: float
    requests_per_second: float
    failed_rate: float


@dataclass(frozen=True)
class LoadBudgetResult:
    """Direct/guard comparison and fixed release budgets."""

    direct: LoadMetrics
    guard: LoadMetrics
    p95_overhead_ms: float
    throughput_reduction_percent: float
    max_p95_overhead_ms: float
    max_throughput_reduction_percent: float
    passed: bool


def load_metrics(path: Path) -> LoadMetrics:
    """Parse only stable k6 summary fields and reject missing/non-numeric values."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        metrics = raw["metrics"]
        duration = _metric_values(metrics["http_req_duration"])
        requests = _metric_values(metrics["http_reqs"])
        failed = _metric_values(metrics["http_req_failed"])
        failed_rate = failed["rate"] if "rate" in failed else failed["value"]
        return LoadMetrics(
            p95_ms=_number(duration["p(95)"]),
            requests_per_second=_number(requests["rate"]),
            failed_rate=_number(failed_rate),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise HarnessError(
            code="LOAD_SUMMARY_INVALID",
            problem="k6 성능 summary를 검증하지 못했습니다.",
            cause=str(error),
            impact="edge 추가 지연과 처리량 release 예산을 판정할 수 없습니다.",
            next_action="direct·guard summary artifact와 k6 버전을 확인하십시오.",
        ) from error


def evaluate(direct: LoadMetrics, guard: LoadMetrics) -> LoadBudgetResult:
    """Apply the fixed NFR-001 latency and throughput budgets."""

    if direct.requests_per_second <= 0:
        raise HarnessError(
            code="LOAD_DIRECT_RATE_INVALID",
            problem="direct origin 처리량이 0입니다.",
            cause="baseline 요청이 실행되지 않았거나 모두 실패했습니다.",
            impact="guard overhead 비교가 무효입니다.",
            next_action="origin fixture와 direct summary를 확인하십시오.",
        )
    p95_overhead_ms = max(0.0, guard.p95_ms - direct.p95_ms)
    throughput_reduction_percent = max(
        0.0,
        (direct.requests_per_second - guard.requests_per_second)
        * 100.0
        / direct.requests_per_second,
    )
    passed = (
        direct.failed_rate == 0
        and guard.failed_rate == 0
        and p95_overhead_ms <= MAX_P95_OVERHEAD_MS
        and throughput_reduction_percent <= MAX_THROUGHPUT_REDUCTION_PERCENT
    )
    return LoadBudgetResult(
        direct=direct,
        guard=guard,
        p95_overhead_ms=p95_overhead_ms,
        throughput_reduction_percent=throughput_reduction_percent,
        max_p95_overhead_ms=MAX_P95_OVERHEAD_MS,
        max_throughput_reduction_percent=MAX_THROUGHPUT_REDUCTION_PERCENT,
        passed=passed,
    )


def run(repo_root: Path) -> LoadBudgetResult:
    """Build Edge, run identical direct/guard k6 workloads and retain bounded evidence."""

    root = repo_root.resolve()
    evidence = root / "target-evidence" / "load"
    evidence.mkdir(parents=True, exist_ok=True)
    runner = CommandRunner()
    runner.run(
        CommandSpec(
            label="guard-edge load artifact build",
            argv=("cargo", "build", "--release", "--locked", "-p", "guard-edge"),
            cwd=root,
            timeout_seconds=900,
            scope=CommandScope.BUILD,
        )
    )
    origin = runner.start(
        BackgroundCommandSpec(
            label="load origin fixture",
            argv=("python3", str(root / "tests/fixtures/origin_server.py")),
            cwd=root,
            startup_seconds=0.1,
            scope=CommandScope.TEST,
        )
    )
    edge: RunningCommand | None = None
    try:
        _wait_http("http://127.0.0.1:18081/health", None, origin)
        env_binary = shutil.which("env")
        if env_binary is None:
            raise HarnessError(
                code="LOAD_ENV_UNAVAILABLE",
                problem="edge fixture 환경을 구성할 env 실행 파일이 없습니다.",
                cause="PATH에서 env를 찾지 못했습니다.",
                impact="NFR-001 비교 부하를 시작하지 않았습니다.",
                next_action="coreutils env가 포함된 실행 환경을 사용하십시오.",
            )
        edge = runner.start(
            BackgroundCommandSpec(
                label="guard-edge load fixture",
                argv=(
                    env_binary,
                    f"VPS_GUARD_CONFIG={root / 'configs/vps-guard.example.toml'}",
                    str(root / "target/release/vps-guard-edge"),
                ),
                cwd=root,
                startup_seconds=0.1,
                scope=CommandScope.TEST,
            )
        )
        _wait_http("http://127.0.0.1:18080/health/live", "example.com", edge)
        direct_path = evidence / "direct.json"
        guard_path = evidence / "guard.json"
        _run_k6(runner, root, direct_path, "http://127.0.0.1:18081/hello")
        _run_k6(runner, root, guard_path, "http://127.0.0.1:18080/hello")
        result = evaluate(load_metrics(direct_path), load_metrics(guard_path))
        report = {
            "schema_version": 1,
            "requirement": "NFR-001",
            "same_host": True,
            "vus": os.environ.get("VUS", DEFAULT_VUS),
            "duration": os.environ.get("DURATION", DEFAULT_DURATION),
            "think_time_ms": 100,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "baseline_kind": "direct-origin-fixture",
            "git_commit": _command(runner, ("git", "rev-parse", "HEAD"), root),
            "rustc": _command(runner, ("rustc", "--version"), root),
            "build_profile": "release",
            "edge_sha256": _sha256(root / "target/release/vps-guard-edge"),
            "config_sha256": _sha256(root / "configs/vps-guard.example.toml"),
            "result": asdict(result),
        }
        (evidence / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if not result.passed:
            raise HarnessError(
                code="LOAD_BUDGET_EXCEEDED",
                problem="guard-edge 성능 예산을 초과했습니다.",
                cause=(
                    f"p95 overhead={result.p95_overhead_ms:.3f}ms, "
                    f"throughput reduction={result.throughput_reduction_percent:.2f}%, "
                    f"failed direct={result.direct.failed_rate}, guard={result.guard.failed_rate}"
                ),
                impact="NFR-001 release gate가 배포를 차단합니다.",
                next_action="동일 artifact로 재측정하고 hot path 회귀를 분석하십시오.",
            )
        return result
    finally:
        _stop(edge)
        _stop(origin)
        try:
            runner.run(
                CommandSpec(
                    label="load gate build storage cleanup",
                    argv=("bash", str(root / "scripts/build-storage.sh"), "--auto"),
                    cwd=root,
                    timeout_seconds=300,
                    scope=CommandScope.BUILD,
                )
            )
        except HarnessError:
            pass


def _run_k6(
    runner: CommandRunner,
    root: Path,
    summary: Path,
    target_url: str,
) -> None:
    vus = os.environ.get("VUS", DEFAULT_VUS)
    duration = os.environ.get("DURATION", DEFAULT_DURATION)
    k6 = shutil.which("k6")
    if k6:
        command = (
            k6,
            "run",
            "-e",
            f"TARGET_URL={target_url}",
            "-e",
            "TARGET_HOST=example.com",
            "-e",
            f"VUS={vus}",
            "-e",
            f"DURATION={duration}",
            "--summary-export",
            str(summary),
            str(root / "tests/load/proxy.js"),
        )
    elif shutil.which("docker"):
        relative_summary = summary.relative_to(root)
        command = (
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{root}:/work",
            "-e",
            f"TARGET_URL={target_url}",
            "-e",
            "TARGET_HOST=example.com",
            "-e",
            f"VUS={vus}",
            "-e",
            f"DURATION={duration}",
            "grafana/k6:0.55.2",
            "run",
            "--summary-export",
            f"/work/{relative_summary}",
            "/work/tests/load/proxy.js",
        )
    else:
        raise HarnessError(
            code="LOAD_RUNNER_UNAVAILABLE",
            problem="k6 load runner가 없습니다.",
            cause="k6와 Docker를 모두 찾지 못했습니다.",
            impact="NFR-001 성능 release gate를 실행할 수 없습니다.",
            next_action="고정 버전 k6 또는 Docker를 설치하십시오.",
        )
    runner.run(
        CommandSpec(
            label=f"k6 load {summary.stem}",
            argv=command,
            cwd=root,
            timeout_seconds=300,
            scope=CommandScope.TEST,
        )
    )


def _wait_http(
    url: str,
    host: str | None,
    process: RunningCommand,
) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not process.is_running:
            raise HarnessError(
                code="LOAD_PROCESS_EXITED",
                problem="성능 fixture 프로세스가 준비 전에 종료되었습니다.",
                cause=f"url={url}",
                impact="기존 listener를 fixture로 오인하지 않고 비교 측정을 중단했습니다.",
                next_action="origin·edge log와 listener 충돌을 확인하십시오.",
            )
        try:
            request = urllib.request.Request(url, headers={"Host": host} if host else {})
            with urllib.request.urlopen(request, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise HarnessError(
        code="LOAD_SERVICE_UNAVAILABLE",
        problem="성능 fixture가 제한 시간 안에 준비되지 않았습니다.",
        cause=url,
        impact="동일 서버 direct·guard 비교를 시작하지 않았습니다.",
        next_action="origin·edge log와 listener 충돌을 확인하십시오.",
    )


def _stop(process: RunningCommand | None) -> None:
    if process is not None:
        process.stop(timeout_seconds=3)


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("metric must be numeric")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError("metric must be finite and non-negative")
    return number


def _metric_values(metric: Any) -> dict[str, Any]:
    if not isinstance(metric, dict):
        raise TypeError("metric must be an object")
    nested = metric.get("values")
    if nested is None:
        return metric
    if not isinstance(nested, dict):
        raise TypeError("metric values must be an object")
    return nested


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _command(runner: CommandRunner, command: tuple[str, ...], cwd: Path) -> str:
    return runner.run(
        CommandSpec(
            label=f"load metadata {command[0]}",
            argv=command,
            cwd=cwd,
            timeout_seconds=10,
            scope=CommandScope.GOVERNANCE,
        )
    ).stdout.strip()


def main() -> int:
    """CLI entrypoint."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.repo_root)
    except HarnessError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        "load regression gate: PASS "
        f"p95-overhead={result.p95_overhead_ms:.3f}ms "
        f"throughput-reduction={result.throughput_reduction_percent:.2f}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
