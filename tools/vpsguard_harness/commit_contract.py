"""Git commit requirement-ID traceability for local and CI revisions."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .errors import HarnessError
from .governance import REQUIREMENT_PATTERN
from .runner import CommandRunner, CommandScope, CommandSpec

_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_ZERO_SHA = "0" * 40


class CommitContractError(HarnessError):
    """A commit range or authored commit violates traceability rules."""


@dataclass(frozen=True)
class CommitRecord:
    """One Git commit with only the fields required by the contract."""

    sha: str
    parent_count: int
    message: str


@dataclass(frozen=True)
class CommitContractSummary:
    """Counts from a successful commit traceability validation."""

    checked: int
    merges_skipped: int

    def display(self) -> str:
        """Return the compact stable gate result."""

        return (
            f"commit contract gate: PASS (checked={self.checked}, "
            f"merges_skipped={self.merges_skipped})"
        )


def validate_commit_records(commits: tuple[CommitRecord, ...]) -> CommitContractSummary:
    """Require a product requirement ID in every non-merge commit message."""

    missing: list[str] = []
    checked = 0
    merges_skipped = 0
    for commit in commits:
        if commit.parent_count > 1:
            merges_skipped += 1
            continue
        checked += 1
        if REQUIREMENT_PATTERN.search(commit.message) is None:
            subject = commit.message.splitlines()[0][:80] if commit.message else "<empty>"
            missing.append(f"{commit.sha[:12]} {subject}")
    if missing:
        raise CommitContractError(
            code="COMMIT_REQUIREMENT_ID_MISSING",
            problem="커밋 요구사항 추적 계약을 통과하지 못했습니다.",
            cause="; ".join(missing),
            impact="코드 변경을 제품 요구사항과 검증 증거에 연결할 수 없습니다.",
            next_action="각 커밋 메시지에 EDGE-003 같은 관련 요구사항 ID를 기록하십시오.",
        )
    return CommitContractSummary(checked=checked, merges_skipped=merges_skipped)


def validate_commit_range(
    root: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> CommitContractSummary:
    """Resolve the current CI or local revision range and validate its commits."""

    env = os.environ if environment is None else environment
    revision = resolve_revision_range(env)
    result = CommandRunner().run(
        CommandSpec(
            label="Git commit traceability",
            argv=("git", "log", "--no-decorate", "--format=%H%x1f%P%x1f%B%x1e", revision),
            cwd=root.resolve(),
            timeout_seconds=30,
            scope=CommandScope.GOVERNANCE,
            max_output_bytes=4_194_304,
        )
    )
    commits = _parse_git_log(result.stdout)
    if not commits:
        raise CommitContractError(
            code="COMMIT_RANGE_EMPTY",
            problem="검사할 Git 커밋을 찾지 못했습니다.",
            cause=f"revision={revision}",
            impact="커밋 요구사항 추적성을 판정하지 않았습니다.",
            next_action="CI event SHA와 현재 Git HEAD를 확인하십시오.",
        )
    return validate_commit_records(commits)


def resolve_revision_range(environment: Mapping[str, str]) -> str:
    """Resolve a bounded Git revision from a trusted GitHub event or local HEAD."""

    event_name = environment.get("GITHUB_EVENT_NAME", "")
    event_path = environment.get("GITHUB_EVENT_PATH", "")
    if event_name in {"pull_request", "push"}:
        if not event_path:
            _raise_event("GITHUB_EVENT_PATH is missing")
        try:
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _raise_event(f"event={event_path}, error={error}")
        if event_name == "pull_request":
            base = payload.get("pull_request", {}).get("base", {}).get("sha", "")
            head = payload.get("pull_request", {}).get("head", {}).get("sha", "")
            return f"{_validate_sha(base)}..{_validate_sha(head)}"
        before = _validate_sha(payload.get("before", ""))
        after = _validate_sha(payload.get("after", ""))
        return f"{after}^..{after}" if before == _ZERO_SHA else f"{before}..{after}"
    return "HEAD^..HEAD"


def _validate_sha(value: object) -> str:
    if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
        _raise_event(f"invalid Git SHA={value!r}")
    return value


def _parse_git_log(output: str) -> tuple[CommitRecord, ...]:
    records: list[CommitRecord] = []
    for raw_record in output.split("\x1e"):
        value = raw_record.strip("\n")
        if not value:
            continue
        fields = value.split("\x1f", maxsplit=2)
        if len(fields) != 3 or _SHA_PATTERN.fullmatch(fields[0]) is None:
            raise CommitContractError(
                code="COMMIT_LOG_FORMAT_INVALID",
                problem="Git 커밋 출력을 해석하지 못했습니다.",
                cause=f"record={value[:120]!r}",
                impact="커밋 요구사항 추적성을 판정하지 않았습니다.",
                next_action="git log format과 저장소 상태를 확인하십시오.",
            )
        parents = tuple(parent for parent in fields[1].split() if parent)
        records.append(CommitRecord(fields[0], len(parents), fields[2].rstrip()))
    return tuple(records)


def _raise_event(cause: str) -> None:
    raise CommitContractError(
        code="COMMIT_EVENT_INVALID",
        problem="CI 커밋 범위를 결정하지 못했습니다.",
        cause=cause,
        impact="커밋 요구사항 추적성을 판정하지 않았습니다.",
        next_action="GitHub event payload의 base, head, before와 after SHA를 확인하십시오.",
    )
