"""Validated TLS-002 private VM manifest and sanitized evidence models."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .errors import HarnessError
from .protection_pilot_model import ProtectionPilotManifest


class TlsReloadError(HarnessError):
    """The TLS reload plan, execution or restore contract failed."""


@dataclass(frozen=True)
class TlsReloadManifest:
    """Strict private VM and TLS reload availability contract."""

    protection: ProtectionPilotManifest
    protection_manifest: Path
    probe_url: str
    probe_host: str
    probe_ip: str
    probe_port: int
    interval_ms: int
    max_outage_ms: int
    drain_wait_seconds: int

    @classmethod
    def load(cls, root: Path, path: Path) -> "TlsReloadManifest":
        """Load an exact repository-bound manifest and reject public targets."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail("TLS_RELOAD_MANIFEST_READ_FAILED", "TLS reload manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "protection_manifest",
            "probe",
        }:
            fail("TLS_RELOAD_MANIFEST_INVALID", "TLS reload manifest field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            fail("TLS_RELOAD_SCHEMA_UNSUPPORTED", "TLS reload schema를 지원하지 않습니다.", repr(raw["schema_version"]))
        protection_path = _repository_path(root, path.parent, raw["protection_manifest"])
        protection = ProtectionPilotManifest.load(protection_path)
        probe = _exact_dict(
            raw["probe"],
            {
                "url",
                "host",
                "ip",
                "port",
                "interval_ms",
                "max_outage_ms",
                "drain_wait_seconds",
            },
        )
        parsed = urlsplit(probe["url"]) if isinstance(probe["url"], str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname != probe["host"]
            or parsed.port != probe["port"]
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            fail(
                "TLS_RELOAD_PROBE_INVALID",
                "TLS reload probe는 credential 없는 exact HTTPS target이어야 합니다.",
                repr(probe),
            )
        try:
            address = ipaddress.ip_address(probe["ip"])
        except (TypeError, ValueError) as error:
            fail("TLS_RELOAD_PROBE_INVALID", "TLS reload probe IP가 올바르지 않습니다.", str(error))
        guest_ip = protection.guest_copy_target.rsplit("@", maxsplit=1)[-1]
        if not address.is_private or str(address) != guest_ip:
            fail(
                "TLS_RELOAD_TARGET_MISMATCH",
                "TLS reload probe는 같은 private guest IP를 사용해야 합니다.",
                f"probe={address}, guest={guest_ip}",
            )
        if (
            probe["host"] != protection.edge_host
            or probe["port"] != 19_443
            or probe["interval_ms"] != 100
            or probe["max_outage_ms"] != 0
            or not isinstance(probe["drain_wait_seconds"], int)
            or isinstance(probe["drain_wait_seconds"], bool)
            or not 6 <= probe["drain_wait_seconds"] <= 30
        ):
            fail(
                "TLS_RELOAD_BOUNDS_INVALID",
                "TLS reload host, port, 100ms interval, zero outage 또는 drain wait가 올바르지 않습니다.",
                repr(probe),
            )
        return cls(
            protection=protection,
            protection_manifest=protection_path,
            probe_url=probe["url"],
            probe_host=probe["host"],
            probe_ip=str(address),
            probe_port=probe["port"],
            interval_ms=probe["interval_ms"],
            max_outage_ms=probe["max_outage_ms"],
            drain_wait_seconds=probe["drain_wait_seconds"],
        )

    @property
    def confirmation(self) -> str:
        """Return the exact isolated VM confirmation token."""

        return self.protection.confirmation


@dataclass(frozen=True)
class TlsReloadSummary:
    """Sanitized TLS reload evidence without PEM, body or credential material."""

    source_commit: str
    original_memory_kib: int
    target_memory_kib: int
    guest_mem_total_kib: int
    balloon_driver_was_loaded: bool
    balloon_driver_restored: bool
    supervisor_pid_before: int
    supervisor_pid_after: int
    initial_certificate_sha256: str
    renewed_certificate_sha256: str
    served_certificate_sha256: str
    inflight_request_started_before_reload: bool
    inflight_connection_reused: bool
    inflight_status_after_reload: int
    worker_drain_ms: int
    tls_probe: dict[str, object]
    public_probe: dict[str, object]
    services_before: dict[str, str]
    services_after: dict[str, str]
    elapsed_ms: int

    def as_dict(self) -> dict[str, object]:
        """Return the stable evidence JSON shape."""

        return {
            "schema_version": 1,
            "result": "PASS",
            **self.__dict__,
            "supervisor_pid_preserved": self.supervisor_pid_before
            == self.supervisor_pid_after,
            "certificate_rotated": self.initial_certificate_sha256
            != self.renewed_certificate_sha256
            == self.served_certificate_sha256,
            "original_memory_restored": True,
            "stores_credentials": False,
            "stores_request_bodies": False,
        }


def fail(code: str, problem: str, cause: str) -> None:
    """Raise one structured fail-closed TLS reload error."""

    raise TlsReloadError(
        code=code,
        problem=problem,
        cause=cause,
        impact="TLS reload 검증과 이후 VM 변경을 중단했습니다.",
        next_action="manifest, 격리 listener, worker log와 restore 결과를 확인하십시오.",
    )


def _repository_path(root: Path, parent: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        fail("TLS_RELOAD_PATH_INVALID", "manifest 경로가 올바르지 않습니다.", repr(value))
    candidate = (parent / value).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        fail("TLS_RELOAD_PATH_ESCAPE", "manifest 경로가 repository를 벗어났습니다.", str(candidate))
    return candidate


def _exact_dict(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail("TLS_RELOAD_MANIFEST_INVALID", "TLS reload probe field가 정확하지 않습니다.", repr(value))
    return value
