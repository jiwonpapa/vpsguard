"""Validated OPS-005/OPS-010 endurance manifest and evidence models."""

from __future__ import annotations

import ipaddress
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .errors import HarnessError
from .protection_pilot_model import ProtectionPilotManifest


class ReleaseEnduranceError(HarnessError):
    """The repeated release transaction or availability budget failed."""


@dataclass(frozen=True)
class ProbeSample:
    """One body-free public availability observation."""

    started_ms: int
    completed_ms: int
    status: int
    exit_code: int


class ProbeAvailability:
    """Accumulate exact-status success and real consecutive outage duration."""

    def __init__(self, *, expected_status: int) -> None:
        self.expected_status = expected_status
        self.samples = 0
        self.successes = 0
        self.failures = 0
        self.status_counts: Counter[int] = Counter()
        self.max_outage_ms = 0
        self.final_status = 0
        self._outage_started_ms: int | None = None

    def observe(self, sample: ProbeSample) -> None:
        """Add one status without retaining a response body."""

        self.samples += 1
        self.status_counts[sample.status] += 1
        self.final_status = sample.status
        success = sample.exit_code == 0 and sample.status == self.expected_status
        if success:
            self.successes += 1
            if self._outage_started_ms is not None:
                self.max_outage_ms = max(
                    self.max_outage_ms,
                    sample.completed_ms - self._outage_started_ms,
                )
                self._outage_started_ms = None
        else:
            self.failures += 1
            if self._outage_started_ms is None:
                self._outage_started_ms = sample.started_ms

    def finish(self, completed_ms: int) -> dict[str, object]:
        """Return the current stable evidence summary."""

        max_outage_ms = self.max_outage_ms
        if self._outage_started_ms is not None:
            max_outage_ms = max(
                max_outage_ms,
                completed_ms - self._outage_started_ms,
            )
        return {
            "samples": self.samples,
            "successes": self.successes,
            "failures": self.failures,
            "status_counts": {
                str(status): count for status, count in sorted(self.status_counts.items())
            },
            "max_outage_ms": max_outage_ms,
            "final_status": self.final_status,
        }


@dataclass(frozen=True)
class ReleaseEnduranceManifest:
    """Strict private VM, public probe and bounded cycle contract."""

    protection: ProtectionPilotManifest
    protection_manifest: Path
    probe_url: str
    probe_host: str
    probe_ip: str
    ca_certificate: Path | None
    expected_status: int
    cycles: int
    interval_ms: int
    max_outage_ms: int
    max_update_ms: int
    max_restore_ms: int

    @classmethod
    def load(cls, root: Path, path: Path) -> "ReleaseEnduranceManifest":
        """Load a repository-bound exact schema and reject public targets."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail("ENDURANCE_MANIFEST_READ_FAILED", "endurance manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "protection_manifest",
            "public_probe",
            "execution",
        }:
            fail("ENDURANCE_MANIFEST_INVALID", "endurance manifest field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            fail("ENDURANCE_SCHEMA_UNSUPPORTED", "endurance schema를 지원하지 않습니다.", repr(raw["schema_version"]))
        protection_path = _repository_path(root, path.parent, raw["protection_manifest"])
        protection = ProtectionPilotManifest.load(protection_path)
        probe = _exact_dict(
            raw["public_probe"],
            {"url", "host", "ip", "ca_certificate", "expected_status"},
            "public_probe",
        )
        execution = _exact_dict(
            raw["execution"],
            {
                "cycles",
                "interval_ms",
                "max_outage_ms",
                "max_update_ms",
                "max_restore_ms",
            },
            "execution",
        )
        parsed = urlsplit(probe["url"]) if isinstance(probe["url"], str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != probe["host"]
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            fail(
                "ENDURANCE_PROBE_INVALID",
                "public probe는 credential 없는 exact HTTPS target이어야 합니다.",
                repr(probe),
            )
        try:
            address = ipaddress.ip_address(probe["ip"])
        except (TypeError, ValueError) as error:
            fail("ENDURANCE_PROBE_INVALID", "public probe IP가 올바르지 않습니다.", str(error))
        guest_ip = protection.guest_copy_target.rsplit("@", maxsplit=1)[-1]
        if not address.is_private or str(address) != guest_ip:
            fail(
                "ENDURANCE_PROBE_TARGET_MISMATCH",
                "public probe는 같은 private guest IP를 사용해야 합니다.",
                f"probe={address}, guest={guest_ip}",
            )
        if probe["host"] != protection.edge_host:
            fail(
                "ENDURANCE_PROBE_HOST_MISMATCH",
                "public probe Host와 Edge Host가 일치하지 않습니다.",
                f"probe={probe['host']}, edge={protection.edge_host}",
            )
        certificate = _certificate_path(probe["ca_certificate"])
        if (
            not isinstance(probe["expected_status"], int)
            or isinstance(probe["expected_status"], bool)
            or not 200 <= probe["expected_status"] <= 399
            or not isinstance(execution["cycles"], int)
            or isinstance(execution["cycles"], bool)
            or not 1 <= execution["cycles"] <= 20
            or execution["interval_ms"] != 100
            or not isinstance(execution["max_outage_ms"], int)
            or isinstance(execution["max_outage_ms"], bool)
            or not 100 <= execution["max_outage_ms"] <= 5_000
            or not isinstance(execution["max_update_ms"], int)
            or isinstance(execution["max_update_ms"], bool)
            or not 100 <= execution["max_update_ms"] <= 60_000
            or not isinstance(execution["max_restore_ms"], int)
            or isinstance(execution["max_restore_ms"], bool)
            or not 100 <= execution["max_restore_ms"] <= 10_000
        ):
            fail(
                "ENDURANCE_EXECUTION_BOUNDS_INVALID",
                "cycle, 100ms interval 또는 실행 budget이 허용 범위 밖입니다.",
                repr(execution),
            )
        return cls(
            protection=protection,
            protection_manifest=protection_path,
            probe_url=probe["url"],
            probe_host=probe["host"],
            probe_ip=str(address),
            ca_certificate=certificate,
            expected_status=probe["expected_status"],
            cycles=execution["cycles"],
            interval_ms=execution["interval_ms"],
            max_outage_ms=execution["max_outage_ms"],
            max_update_ms=execution["max_update_ms"],
            max_restore_ms=execution["max_restore_ms"],
        )

    @property
    def confirmation(self) -> str:
        """Return the private VM's exact confirmation token."""

        return self.protection.confirmation


@dataclass(frozen=True)
class ReleaseCycleResult:
    """One successful update, candidate read-back and exact restore."""

    cycle: int
    snapshot: str
    update_ms: int
    restore_ms: int
    candidate_release: str
    restored_release: str
    services_restored: bool


@dataclass(frozen=True)
class ReleaseEnduranceSummary:
    """Sanitized 20-cycle evidence without credentials or response bodies."""

    source_commit: str
    original_release: str
    restored_release: str
    original_memory_kib: int
    target_memory_kib: int
    guest_mem_total_kib: int
    balloon_driver_was_loaded: bool
    balloon_driver_restored: bool
    cycles_requested: int
    cycles_completed: int
    cycles: tuple[ReleaseCycleResult, ...]
    probe: dict[str, object]
    services_before: dict[str, str]
    services_after: dict[str, str]
    elapsed_ms: int

    def as_dict(self) -> dict[str, object]:
        """Return the stable JSON evidence shape."""

        return {
            "schema_version": 1,
            "result": "PASS",
            **self.__dict__,
            "cycles": [cycle.__dict__ for cycle in self.cycles],
            "original_release_restored": self.original_release == self.restored_release,
            "original_memory_restored": True,
            "stores_credentials": False,
            "stores_response_bodies": False,
            "stores_request_bodies": False,
        }


def public_probe_command(manifest: ReleaseEnduranceManifest) -> tuple[str, ...]:
    """Build an exact TLS, body-free curl argv for the private guest."""

    parsed = urlsplit(manifest.probe_url)
    port = parsed.port or 443
    command = [
        "curl",
        "--disable",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}\t%{time_total}",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
    ]
    if manifest.ca_certificate is not None:
        command.extend(("--cacert", str(manifest.ca_certificate)))
    command.extend(
        (
            "--resolve",
            f"{manifest.probe_host}:{port}:{manifest.probe_ip}",
            manifest.probe_url,
        )
    )
    return tuple(command)


def fail(code: str, problem: str, cause: str) -> None:
    """Raise one structured fail-closed endurance error."""

    raise ReleaseEnduranceError(
        code=code,
        problem=problem,
        cause=cause,
        impact="격리 VM endurance 다음 cycle을 중단하고 원상복구를 시도했습니다.",
        next_action="release·memory·service·public probe와 남은 stage·snapshot을 확인하십시오.",
    )


def _repository_path(root: Path, parent: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        fail(
            "ENDURANCE_PROTECTION_MANIFEST_INVALID",
            "protection manifest는 상대 경로여야 합니다.",
            repr(value),
        )
    candidate = (parent / value).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        fail(
            "ENDURANCE_PROTECTION_MANIFEST_INVALID",
            "protection manifest 경계를 벗어났습니다.",
            str(candidate),
        )
    return candidate


def _certificate_path(value: object) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str):
        fail("ENDURANCE_CA_INVALID", "CA certificate 경로가 올바르지 않습니다.", repr(value))
    path = Path(value)
    if not path.is_absolute() or path.name.endswith("-key.pem"):
        fail("ENDURANCE_CA_INVALID", "공개 CA certificate 절대 경로만 허용합니다.", str(path))
    return path


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail("ENDURANCE_MANIFEST_INVALID", f"{label} field가 정확하지 않습니다.", repr(value))
    return value
