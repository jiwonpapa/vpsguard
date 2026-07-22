"""Typed Rustdoc and requirement traceability repository gates."""

from __future__ import annotations

import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError

REQUIREMENT_PATTERN = re.compile(r"(?:EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}")
RUSTDOC_DOWNGRADE_PATTERN = re.compile(
    r"#!?\[\s*(?:allow|warn|expect)\s*\([^\]]*missing_docs"
)
VERIFICATION_STATUSES = {"PLANNED", "CODE_ONLY", "AUTO_PASS", "VPS_PASS"}


class GovernanceError(HarnessError):
    """A source-of-truth governance contract was violated."""


@dataclass(frozen=True)
class RequirementSummary:
    """Counts returned by a successful requirement registry validation."""

    total: int
    planned: int
    code_only: int
    auto_pass: int
    vps_pass: int

    def display(self) -> str:
        """Return the stable user-facing gate result."""

        return (
            f"requirements gate: PASS ({self.total} IDs; PLANNED={self.planned}, "
            f"CODE_ONLY={self.code_only}, AUTO_PASS={self.auto_pass}, "
            f"VPS_PASS={self.vps_pass})"
        )


def validate_rustdoc(root: Path) -> None:
    """Validate workspace missing-docs inheritance and module-level Rustdoc."""

    violations: list[str] = []
    workspace_path = root / "Cargo.toml"
    workspace = _read_toml(workspace_path)
    missing_docs = (
        workspace.get("workspace", {})
        .get("lints", {})
        .get("rust", {})
        .get("missing_docs")
    )
    if missing_docs != "deny":
        violations.append(f"workspace missing_docs lint must be deny: {workspace_path.relative_to(root)}")

    crates = root / "crates"
    for manifest in sorted(crates.glob("*/Cargo.toml")):
        parsed = _read_toml(manifest)
        if parsed.get("lints", {}).get("workspace") is not True:
            violations.append(f"crate must inherit workspace lints: {manifest.relative_to(root)}")

    for source in sorted(crates.rglob("*.rs")):
        text = source.read_text(encoding="utf-8")
        first_line = text.splitlines()[0] if text else ""
        if not first_line.startswith("//!"):
            violations.append(f"missing module rustdoc: {source.relative_to(root)}")
        if RUSTDOC_DOWNGRADE_PATTERN.search(text):
            violations.append(f"missing_docs lint downgrade is forbidden: {source.relative_to(root)}")

    if violations:
        _raise_governance(
            "RUSTDOC_CONTRACT_FAILED",
            "Rust 문서화 계약을 통과하지 못했습니다.",
            violations,
            "Rustdoc 품질 게이트와 코드 정본 신뢰성을 보장할 수 없습니다.",
            "표시된 module 문서와 workspace lint 상속을 복구하십시오.",
        )


def validate_requirements(root: Path, *, release: bool) -> RequirementSummary:
    """Validate requirement IDs, evidence paths and proof-level claims."""

    product = root / "specs/product"
    contract_ids = _requirement_ids(product / "06-requirements-contracts.md")
    trace_ids = _requirement_ids(product / "07-verification-traceability.md")
    if contract_ids != trace_ids:
        missing = sorted(contract_ids - trace_ids)
        extra = sorted(trace_ids - contract_ids)
        details = [*(f"missing from traceability: {value}" for value in missing)]
        details.extend(f"unknown in traceability: {value}" for value in extra)
        _raise_governance(
            "REQUIREMENTS_TRACE_MISMATCH",
            "요구사항과 검증 추적표가 일치하지 않습니다.",
            details,
            "구현 완료와 검증 증거를 요구사항별로 판정할 수 없습니다.",
            "계약과 추적표의 요구사항 ID를 같은 변경에서 맞추십시오.",
        )

    rows = _verification_rows(product / "verification-status.tsv")
    registry_ids = [row[0] for row in rows]
    duplicates = sorted(value for value, count in Counter(registry_ids).items() if count > 1)
    if duplicates:
        _raise_governance(
            "VERIFICATION_REGISTRY_DUPLICATE",
            "검증 상태표에 중복 요구사항이 있습니다.",
            duplicates,
            "어느 proof level이 정본인지 판정할 수 없습니다.",
            "각 요구사항 ID를 한 행만 남기십시오.",
        )

    registry_set = set(registry_ids)
    if contract_ids != registry_set:
        missing = sorted(contract_ids - registry_set)
        extra = sorted(registry_set - contract_ids)
        details = [*(f"missing from registry: {value}" for value in missing)]
        details.extend(f"unknown in registry: {value}" for value in extra)
        _raise_governance(
            "VERIFICATION_REGISTRY_MISMATCH",
            "요구사항과 검증 상태표가 일치하지 않습니다.",
            details,
            "현재 구현·자동 검증·VPS 증거 수준을 판정할 수 없습니다.",
            "verification-status.tsv를 요구사항 계약과 맞추십시오.",
        )

    violations: list[str] = []
    statuses: Counter[str] = Counter()
    for requirement, status, implementation, automated, operational in rows:
        statuses[status] += 1
        if status not in VERIFICATION_STATUSES:
            violations.append(f"{requirement}: unknown status {status}")
            continue
        if status == "PLANNED":
            if (implementation, automated, operational) != ("-", "-", "-"):
                violations.append(f"{requirement}: PLANNED must not claim evidence")
            continue
        if not _evidence_exists(root, implementation):
            violations.append(f"{requirement}: missing implementation evidence {implementation}")
        if status in {"AUTO_PASS", "VPS_PASS"} and not _evidence_exists(root, automated):
            violations.append(f"{requirement}: missing automated evidence {automated}")
        if status == "VPS_PASS" and not _evidence_exists(root, operational):
            violations.append(f"{requirement}: missing operational evidence {operational}")

    if violations:
        _raise_governance(
            "VERIFICATION_EVIDENCE_INVALID",
            "검증 상태표의 증거 계약을 통과하지 못했습니다.",
            violations,
            "proof level이 실제 파일 증거보다 높게 표시될 수 있습니다.",
            "상태를 낮추거나 누락된 증거를 추가하십시오.",
        )

    summary = RequirementSummary(
        total=len(contract_ids),
        planned=statuses["PLANNED"],
        code_only=statuses["CODE_ONLY"],
        auto_pass=statuses["AUTO_PASS"],
        vps_pass=statuses["VPS_PASS"],
    )
    if release and summary.planned + summary.code_only > 0:
        raise GovernanceError(
            code="RELEASE_REQUIREMENTS_INCOMPLETE",
            problem="release gate blocked: 릴리스 요구사항 게이트가 차단됐습니다.",
            cause=(
                f"PLANNED={summary.planned}, CODE_ONLY={summary.code_only}, "
                f"AUTO_PASS={summary.auto_pass}, VPS_PASS={summary.vps_pass}"
            ),
            impact="현재 revision을 검증 완료 릴리스로 판정하지 않았습니다.",
            next_action="미완료 요구사항의 자동·운영 증거를 수집하십시오.",
        )
    return summary


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GovernanceError(
            code="GOVERNANCE_TOML_INVALID",
            problem="거버넌스 TOML을 읽지 못했습니다.",
            cause=f"path={path}, error={error}",
            impact="관련 repository gate를 실행하지 않았습니다.",
            next_action="파일 존재와 TOML 문법을 확인하십시오.",
        ) from error


def _requirement_ids(path: Path) -> set[str]:
    return set(REQUIREMENT_PATTERN.findall(path.read_text(encoding="utf-8")))


def _verification_rows(path: Path) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 5:
            _raise_governance(
                "VERIFICATION_REGISTRY_FORMAT_INVALID",
                "검증 상태표 행 형식이 올바르지 않습니다.",
                [f"line={line_number}, fields={len(fields)}"],
                "해당 행과 이후 proof level을 판정하지 않았습니다.",
                "requirement|status|implementation|automated|operational 5개 필드를 사용하십시오.",
            )
        rows.append((fields[0], fields[1], fields[2], fields[3], fields[4]))
    return rows


def _evidence_exists(root: Path, value: str) -> bool:
    if value == "-":
        return False
    evidence = Path(value)
    if evidence.is_absolute() or ".." in evidence.parts:
        return False
    repository = root.resolve()
    candidate = (repository / evidence).resolve(strict=False)
    return candidate.is_relative_to(repository) and candidate.exists()


def _raise_governance(
    code: str,
    problem: str,
    details: list[str],
    impact: str,
    next_action: str,
) -> None:
    raise GovernanceError(
        code=code,
        problem=problem,
        cause="; ".join(details),
        impact=impact,
        next_action=next_action,
    )
