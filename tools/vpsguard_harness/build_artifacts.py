"""Bounded repository-local Cargo artifact storage and cleanup policy."""

from __future__ import annotations

import os
import re
import shutil
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import HarnessError

PRESERVED_TARGET_ENTRIES = frozenset({"CACHEDIR.TAG", "evidence", "release-bundle"})
REGENERABLE_TARGET_ENTRIES = frozenset(
    {
        ".rustc_info.json",
        "debug",
        "doc",
        "integration-trace.log",
        "llvm-cov-target",
        "package",
        "release",
        "release-download",
        "tmp",
    }
)
TARGET_TRIPLE_PATTERN = re.compile(r"^[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+){2,}$")


class BuildArtifactError(HarnessError):
    """Build storage configuration or repository cleanup boundary failed."""


@dataclass(frozen=True)
class BuildArtifactSummary:
    """One storage plan or cleanup result using allocated filesystem bytes."""

    applied: bool
    target_bytes: int
    reclaimable_bytes: int
    reclaimed_bytes: int
    candidates: tuple[str, ...]
    preserved: tuple[str, ...]
    skipped: tuple[str, ...]

    def display(self) -> str:
        """Return a concise plan or cleanup report."""

        action = "cleaned" if self.applied else "plan"
        return (
            f"build storage {action}: target={_format_bytes(self.target_bytes)} "
            f"reclaimable={_format_bytes(self.reclaimable_bytes)} "
            f"reclaimed={_format_bytes(self.reclaimed_bytes)} "
            f"candidates={len(self.candidates)} preserved={len(self.preserved)} "
            f"skipped={len(self.skipped)}"
        )


@dataclass
class _InodeUsage:
    allocated_bytes: int
    link_count: int
    is_directory: bool
    occurrences: int = 0
    categories: set[str] = field(default_factory=set)


def validate_build_profiles(root: Path) -> None:
    """Require low-storage dev/test profiles without incremental state."""

    manifest = root / "Cargo.toml"
    try:
        with manifest.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise BuildArtifactError(
            code="BUILD_PROFILE_MANIFEST_INVALID",
            problem="Cargo build profile을 읽지 못했습니다.",
            cause=f"path={manifest}, error={error}",
            impact="개발·테스트 산출물 저장공간 정책을 검증하지 않았습니다.",
            next_action="Cargo.toml 존재와 TOML 문법을 확인하십시오.",
        ) from error

    violations: list[str] = []
    profiles = parsed.get("profile", {})
    if not isinstance(profiles, dict):
        profiles = {}
    for name in ("dev", "test"):
        profile = profiles.get(name, {})
        if not isinstance(profile, dict):
            profile = {}
        if profile.get("debug") != 1:
            violations.append(f"profile.{name}.debug must be 1")
        if profile.get("incremental") is not False:
            violations.append(f"profile.{name}.incremental must be false")
        packages = profile.get("package", {})
        dependency = packages.get("*", {}) if isinstance(packages, dict) else {}
        if not isinstance(dependency, dict) or dependency.get("debug") is not False:
            violations.append(f'profile.{name}.package."*".debug must be false')

    if violations:
        raise BuildArtifactError(
            code="BUILD_PROFILE_STORAGE_POLICY_FAILED",
            problem="Cargo 개발 산출물 저장공간 정책을 통과하지 못했습니다.",
            cause="; ".join(violations),
            impact="debug symbol과 incremental cache가 로컬 디스크에서 무제한 누적될 수 있습니다.",
            next_action="dev/test debug=1, incremental=false와 dependency debug=false를 복구하십시오.",
        )


def clean_build_artifacts(root: Path, *, apply: bool) -> BuildArtifactSummary:
    """Plan or remove regenerable target entries while preserving release evidence."""

    repository = root.resolve()
    target = repository / "target"
    if not target.exists():
        return BuildArtifactSummary(apply, 0, 0, 0, (), (), ())
    if target.is_symlink() or not target.is_dir():
        raise BuildArtifactError(
            code="BUILD_TARGET_BOUNDARY_INVALID",
            problem="빌드 산출물 경계를 안전하게 확인하지 못했습니다.",
            cause=f"target must be a real directory below repository: {target}",
            impact="어떤 파일도 삭제하지 않았습니다.",
            next_action="target symlink 또는 비정상 파일을 제거하고 다시 실행하십시오.",
        )

    entries = sorted(target.iterdir(), key=lambda path: path.name)
    candidates = tuple(entry for entry in entries if _is_regenerable(entry.name))
    preserved = tuple(entry for entry in entries if entry.name in PRESERVED_TARGET_ENTRIES)
    skipped = tuple(entry for entry in entries if entry not in candidates and entry not in preserved)
    candidate_names = {entry.name for entry in candidates}
    preserved_names = {entry.name for entry in preserved}
    inodes: dict[tuple[int, int], _InodeUsage] = {}
    for entry in entries:
        category = (
            "candidate"
            if entry.name in candidate_names
            else "preserved"
            if entry.name in preserved_names
            else "skipped"
        )
        _scan_path(entry, category, inodes)
    target_bytes = sum(usage.allocated_bytes for usage in inodes.values())
    reclaimable_bytes = sum(
        usage.allocated_bytes
        for usage in inodes.values()
        if usage.categories == {"candidate"}
        and (usage.is_directory or usage.occurrences >= usage.link_count)
    )

    if apply:
        for candidate in candidates:
            try:
                _remove(candidate)
            except OSError as error:
                raise BuildArtifactError(
                    code="BUILD_ARTIFACT_CLEAN_FAILED",
                    problem="재생성 가능한 빌드 산출물을 모두 정리하지 못했습니다.",
                    cause=f"path={candidate}, error={error}",
                    impact="앞선 항목 일부는 삭제됐을 수 있지만 보존 항목은 건드리지 않았습니다.",
                    next_action="파일 사용 프로세스와 권한을 확인한 뒤 정리 계획을 다시 실행하십시오.",
                ) from error

    return BuildArtifactSummary(
        applied=apply,
        target_bytes=target_bytes,
        reclaimable_bytes=reclaimable_bytes,
        reclaimed_bytes=reclaimable_bytes if apply else 0,
        candidates=tuple(path.name for path in candidates),
        preserved=tuple(path.name for path in preserved),
        skipped=tuple(path.name for path in skipped),
    )


def _is_regenerable(name: str) -> bool:
    return (
        name in REGENERABLE_TARGET_ENTRIES
        or name.startswith("ci-run-")
        or TARGET_TRIPLE_PATTERN.fullmatch(name) is not None
    ) and name not in PRESERVED_TARGET_ENTRIES


def _scan_path(
    path: Path,
    category: str,
    inodes: dict[tuple[int, int], _InodeUsage],
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BuildArtifactError(
            code="BUILD_ARTIFACT_SCAN_FAILED",
            problem="빌드 산출물 크기를 계산하지 못했습니다.",
            cause=f"path={path}, error={error}",
            impact="정리 예상 용량을 확정하지 않았습니다.",
            next_action="파일 권한과 사용 중인 빌드 프로세스를 확인하십시오.",
        ) from error
    key = (metadata.st_dev, metadata.st_ino)
    usage = inodes.get(key)
    if usage is None:
        usage = _InodeUsage(
            allocated_bytes=_metadata_bytes(metadata),
            link_count=metadata.st_nlink,
            is_directory=stat.S_ISDIR(metadata.st_mode),
        )
        inodes[key] = usage
    usage.occurrences += 1
    usage.categories.add(category)
    if not usage.is_directory or path.is_symlink():
        return
    try:
        with os.scandir(path) as children:
            for child in children:
                _scan_path(Path(child.path), category, inodes)
    except OSError as error:
        raise BuildArtifactError(
            code="BUILD_ARTIFACT_SCAN_FAILED",
            problem="빌드 산출물 directory를 검사하지 못했습니다.",
            cause=f"path={path}, error={error}",
            impact="정리 예상 용량을 확정하지 않았습니다.",
            next_action="파일 권한과 사용 중인 빌드 프로세스를 확인하십시오.",
        ) from error


def _metadata_bytes(metadata: os.stat_result) -> int:
    blocks = getattr(metadata, "st_blocks", 0)
    return blocks * 512 if blocks else metadata.st_size


def _remove(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def _format_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f}{unit}" if unit != "B" else f"{int(amount)}B"
        amount /= 1024
    return f"{value}B"
