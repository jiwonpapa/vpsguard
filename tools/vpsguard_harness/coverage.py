"""LCOV coverage ratchets for the workspace and named production files."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError


class CoverageError(HarnessError):
    """Coverage evidence or its non-decreasing baseline is invalid."""


@dataclass(frozen=True)
class CoverageSummary:
    """Successful workspace and production-file coverage result."""

    workspace_percent: float
    checked_files: int

    def display(self) -> str:
        """Return the stable coverage gate summary."""

        return (
            f"coverage ratchet: PASS (workspace={self.workspace_percent:.2f}%, "
            f"critical_files={self.checked_files})"
        )


def validate_coverage(root: Path, lcov_path: Path, baseline_path: Path) -> CoverageSummary:
    """Validate LCOV totals and every named production-file floor.

    Paths outside ``root`` and baseline entries absent from LCOV fail closed so
    process or network adapters cannot silently disappear from the report.
    """

    repository = root.resolve()
    workspace_floor, file_floors = _read_baseline(baseline_path)
    coverage = _read_lcov(repository, lcov_path)
    total_lines = sum(len(lines) for lines in coverage.values())
    covered_lines = sum(
        sum(1 for count in lines.values() if count > 0) for lines in coverage.values()
    )
    if total_lines == 0:
        raise CoverageError(
            code="COVERAGE_EVIDENCE_EMPTY",
            problem="LCOV 검증 증거가 비어 있습니다.",
            cause=f"path={lcov_path}",
            impact="workspace와 핵심 운영 파일의 회귀 여부를 판정하지 않았습니다.",
            next_action="cargo llvm-cov로 LCOV를 다시 생성하십시오.",
        )

    workspace_percent = _percent(covered_lines, total_lines)
    violations: list[str] = []
    if workspace_percent + 1e-9 < workspace_floor:
        violations.append(
            f"workspace={workspace_percent:.2f}% below {workspace_floor:.2f}%"
        )
    for relative, minimum in sorted(file_floors.items()):
        lines = coverage.get(relative)
        if lines is None:
            violations.append(f"{relative}=missing from LCOV")
            continue
        actual = _percent(sum(1 for count in lines.values() if count > 0), len(lines))
        if actual + 1e-9 < minimum:
            violations.append(f"{relative}={actual:.2f}% below {minimum:.2f}%")
    if violations:
        raise CoverageError(
            code="COVERAGE_RATCHET_FAILED",
            problem="커버리지 하락 방지 기준을 통과하지 못했습니다.",
            cause="; ".join(violations),
            impact="핵심 운영 경로의 테스트 회귀가 병합될 수 있습니다.",
            next_action="누락 테스트를 복구하고 실제 상승분만 baseline에 반영하십시오.",
        )
    return CoverageSummary(workspace_percent, len(file_floors))


def _read_baseline(path: Path) -> tuple[float, dict[str, float]]:
    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CoverageError(
            code="COVERAGE_BASELINE_INVALID",
            problem="커버리지 기준 파일을 읽지 못했습니다.",
            cause=f"path={path}, error={error}",
            impact="커버리지 게이트를 실행하지 않았습니다.",
            next_action="baseline 파일과 TOML 문법을 확인하십시오.",
        ) from error
    if parsed.get("schema_version") != 1:
        raise _baseline_schema_error("schema_version must be 1")
    workspace = parsed.get("workspace")
    files = parsed.get("files")
    if not isinstance(workspace, dict) or not isinstance(files, dict):
        raise _baseline_schema_error("workspace and files tables are required")
    workspace_floor = _floor(workspace.get("minimum_line_percent"), "workspace")
    file_floors: dict[str, float] = {}
    for relative, value in files.items():
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise _baseline_schema_error(f"unsafe file path: {relative}")
        file_floors[relative] = _floor(value, relative)
    return workspace_floor, file_floors


def _read_lcov(root: Path, path: Path) -> dict[str, dict[int, int]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CoverageError(
            code="COVERAGE_EVIDENCE_INVALID",
            problem="LCOV 검증 증거를 읽지 못했습니다.",
            cause=f"path={path}, error={error}",
            impact="커버리지 회귀 여부를 판정하지 않았습니다.",
            next_action="coverage 실행 결과와 파일 권한을 확인하십시오.",
        ) from error
    current: str | None = None
    result: dict[str, dict[int, int]] = {}
    for raw in lines:
        if raw.startswith("SF:"):
            source = Path(raw[3:])
            resolved = (source if source.is_absolute() else root / source).resolve(strict=False)
            if not resolved.is_relative_to(root):
                raise CoverageError(
                    code="COVERAGE_SOURCE_OUTSIDE_REPOSITORY",
                    problem="LCOV에 저장소 밖 source가 포함됐습니다.",
                    cause=f"source={resolved}",
                    impact="workspace 커버리지 분모를 신뢰할 수 없습니다.",
                    next_action="repository source만 계측하도록 coverage 명령을 확인하십시오.",
                )
            current = resolved.relative_to(root).as_posix()
            result.setdefault(current, {})
        elif raw.startswith("DA:") and current is not None:
            fields = raw[3:].split(",", maxsplit=2)
            if len(fields) < 2:
                continue
            try:
                line_number = int(fields[0])
                count = int(fields[1])
            except ValueError:
                continue
            previous = result[current].get(line_number, 0)
            result[current][line_number] = max(previous, count)
        elif raw == "end_of_record":
            current = None
    return result


def _floor(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise _baseline_schema_error(f"{label} floor must be numeric")
    floor = float(value)
    if not 0.0 <= floor <= 100.0:
        raise _baseline_schema_error(f"{label} floor must be within 0..100")
    return floor


def _baseline_schema_error(cause: str) -> CoverageError:
    return CoverageError(
        code="COVERAGE_BASELINE_INVALID",
        problem="커버리지 기준 schema가 올바르지 않습니다.",
        cause=cause,
        impact="커버리지 게이트를 실행하지 않았습니다.",
        next_action="versioned baseline의 workspace와 files 기준을 수정하십시오.",
    )


def _percent(covered: int, total: int) -> float:
    return 100.0 if total == 0 else covered * 100.0 / total
