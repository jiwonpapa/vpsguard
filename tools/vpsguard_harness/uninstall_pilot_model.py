"""Validated OPS-006 private VM uninstall and exact-restore evidence models."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .release_endurance_model import ReleaseEnduranceManifest


class UninstallPilotError(HarnessError):
    """The uninstall plan, preservation check or restore contract failed."""


@dataclass(frozen=True)
class UninstallPilotManifest:
    """Strict Apache bypass, 2GB VM and bounded uninstall contract."""

    endurance: ReleaseEnduranceManifest
    endurance_manifest: Path
    ingress: str
    max_uninstall_ms: int
    max_restore_ms: int

    @classmethod
    def load(cls, root: Path, path: Path) -> "UninstallPilotManifest":
        """Load an exact repository-bound manifest and reject non-Apache targets."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(
                "UNINSTALL_MANIFEST_READ_FAILED",
                "uninstall manifest를 읽지 못했습니다.",
                str(error),
            )
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "release_endurance_manifest",
            "ingress",
            "execution",
        }:
            fail(
                "UNINSTALL_MANIFEST_INVALID",
                "uninstall manifest field가 정확하지 않습니다.",
                repr(raw),
            )
        if raw["schema_version"] != 1:
            fail(
                "UNINSTALL_SCHEMA_UNSUPPORTED",
                "uninstall manifest schema를 지원하지 않습니다.",
                repr(raw["schema_version"]),
            )
        endurance_path = _repository_path(
            root,
            path.parent,
            raw["release_endurance_manifest"],
        )
        try:
            endurance = ReleaseEnduranceManifest.load(root, endurance_path)
        except HarnessError as error:
            fail(
                "UNINSTALL_TARGET_INVALID",
                "uninstall 대상 VM 또는 public probe가 올바르지 않습니다.",
                error.cause,
            )
        execution = raw["execution"]
        if not isinstance(execution, dict) or set(execution) != {
            "max_uninstall_ms",
            "max_restore_ms",
        }:
            fail(
                "UNINSTALL_EXECUTION_INVALID",
                "uninstall 실행 budget field가 정확하지 않습니다.",
                repr(execution),
            )
        max_uninstall_ms = execution["max_uninstall_ms"]
        max_restore_ms = execution["max_restore_ms"]
        if (
            raw["ingress"] != "apache-public"
            or endurance.protection.domain != "gnuboard5"
            or not isinstance(max_uninstall_ms, int)
            or isinstance(max_uninstall_ms, bool)
            or not 1_000 <= max_uninstall_ms <= 30_000
            or not isinstance(max_restore_ms, int)
            or isinstance(max_restore_ms, bool)
            or not 1_000 <= max_restore_ms <= 30_000
        ):
            fail(
                "UNINSTALL_BOUNDS_INVALID",
                "Apache ingress, 격리 domain 또는 실행 budget이 올바르지 않습니다.",
                (
                    f"ingress={raw['ingress']}, domain={endurance.protection.domain}, "
                    f"uninstall={max_uninstall_ms}, restore={max_restore_ms}"
                ),
            )
        return cls(
            endurance=endurance,
            endurance_manifest=endurance_path,
            ingress=raw["ingress"],
            max_uninstall_ms=max_uninstall_ms,
            max_restore_ms=max_restore_ms,
        )

    @property
    def confirmation(self) -> str:
        """Return the exact isolated VM confirmation token."""

        return self.endurance.confirmation


@dataclass(frozen=True)
class UninstallPilotSummary:
    """Sanitized uninstall evidence without site content or credential material."""

    source_commit: str
    original_release: str
    restored_release: str
    original_memory_kib: int
    target_memory_kib: int
    guest_mem_total_kib: int
    balloon_driver_was_loaded: bool
    balloon_driver_restored: bool
    release_directories: int
    release_files: int
    bypass_ms: int
    uninstall_ms: int
    restore_ms: int
    reenable_ms: int
    public_probe: dict[str, object]
    services_before: dict[str, str]
    services_after: dict[str, str]
    post_uninstall: dict[str, object]
    protected_fingerprints: dict[str, str]
    protected_listener_ports: tuple[int, ...]
    recovery_artifacts_retained: int
    elapsed_ms: int

    def as_dict(self) -> dict[str, object]:
        """Return the stable JSON evidence shape."""

        return {
            "schema_version": 1,
            "result": "PASS",
            **self.__dict__,
            "protected_listener_ports": list(self.protected_listener_ports),
            "original_release_restored": self.original_release == self.restored_release,
            "original_memory_restored": True,
            "protected_state_restored": True,
            "stores_credentials": False,
            "stores_site_content": False,
            "stores_response_bodies": False,
            "stores_request_bodies": False,
        }


def fail(code: str, problem: str, cause: str) -> None:
    """Raise one structured fail-closed uninstall error."""

    raise UninstallPilotError(
        code=code,
        problem=problem,
        cause=cause,
        impact="uninstall 다음 단계를 중단하고 격리 VM 원상복구를 시도했습니다.",
        next_action="deployment snapshot, release backup, Apache topology와 public probe를 확인하십시오.",
    )


def _repository_path(root: Path, parent: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        fail("UNINSTALL_PATH_INVALID", "manifest 경로가 올바르지 않습니다.", repr(value))
    candidate = (parent / value).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        fail(
            "UNINSTALL_PATH_ESCAPE",
            "manifest 경로가 repository를 벗어났습니다.",
            str(candidate),
        )
    return candidate
