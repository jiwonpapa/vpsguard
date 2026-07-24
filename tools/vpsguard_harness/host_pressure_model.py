"""Validated DET-014 private 2GB pressure manifest and evidence model."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .errors import HarnessError
from .protection_pilot_model import ProtectionPilotManifest


class HostPressureError(HarnessError):
    """The isolated host-pressure proof violated a bounded invariant."""


@dataclass(frozen=True)
class HostPressureManifest:
    """Strict private VM, public probe and CPU pressure execution contract."""

    protection: ProtectionPilotManifest
    protection_manifest: Path
    probe_url: str
    probe_host: str
    probe_ip: str
    ca_certificate: Path | None
    expected_status: int
    pressure_seconds: int
    recovery_timeout_seconds: int
    sample_interval_ms: int
    request_interval_ms: int
    cpu_workers: int
    probe_interval_ms: int
    max_outage_ms: int

    @classmethod
    def load(cls, root: Path, path: Path) -> "HostPressureManifest":
        """Load one exact repository-bound manifest and reject public targets."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail("PRESSURE_MANIFEST_READ_FAILED", "pressure manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "protection_manifest",
            "public_probe",
            "execution",
        }:
            fail("PRESSURE_MANIFEST_INVALID", "pressure manifest field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            fail("PRESSURE_SCHEMA_UNSUPPORTED", "pressure schema를 지원하지 않습니다.", repr(raw["schema_version"]))
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
                "pressure_seconds",
                "recovery_timeout_seconds",
                "sample_interval_ms",
                "request_interval_ms",
                "cpu_workers",
                "probe_interval_ms",
                "max_outage_ms",
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
                "PRESSURE_PROBE_INVALID",
                "public probe는 credential 없는 exact HTTPS target이어야 합니다.",
                repr(probe),
            )
        try:
            address = ipaddress.ip_address(probe["ip"])
        except (TypeError, ValueError) as error:
            fail("PRESSURE_PROBE_INVALID", "public probe IP가 올바르지 않습니다.", str(error))
        guest_ip = protection.guest_copy_target.rsplit("@", maxsplit=1)[-1]
        if not address.is_private or str(address) != guest_ip:
            fail(
                "PRESSURE_PROBE_TARGET_MISMATCH",
                "public probe는 같은 private guest IP를 사용해야 합니다.",
                f"probe={address}, guest={guest_ip}",
            )
        if probe["host"] != protection.edge_host:
            fail(
                "PRESSURE_PROBE_HOST_MISMATCH",
                "public probe Host와 Edge Host가 일치하지 않습니다.",
                f"probe={probe['host']}, edge={protection.edge_host}",
            )
        certificate = _certificate_path(probe["ca_certificate"])
        if (
            not isinstance(probe["expected_status"], int)
            or isinstance(probe["expected_status"], bool)
            or not 200 <= probe["expected_status"] <= 399
            or not _integer_between(execution["pressure_seconds"], 20, 120)
            or not _integer_between(execution["recovery_timeout_seconds"], 20, 120)
            or execution["sample_interval_ms"] != 1_000
            or not _integer_between(execution["request_interval_ms"], 1_000, 5_000)
            or not _integer_between(execution["cpu_workers"], 1, 64)
            or execution["probe_interval_ms"] != 100
            or not _integer_between(execution["max_outage_ms"], 100, 5_000)
        ):
            fail(
                "PRESSURE_EXECUTION_BOUNDS_INVALID",
                "pressure, recovery, worker 또는 probe budget이 허용 범위 밖입니다.",
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
            pressure_seconds=execution["pressure_seconds"],
            recovery_timeout_seconds=execution["recovery_timeout_seconds"],
            sample_interval_ms=execution["sample_interval_ms"],
            request_interval_ms=execution["request_interval_ms"],
            cpu_workers=execution["cpu_workers"],
            probe_interval_ms=execution["probe_interval_ms"],
            max_outage_ms=execution["max_outage_ms"],
        )

    @property
    def confirmation(self) -> str:
        """Return the private VM's exact confirmation token."""

        return self.protection.confirmation

    @property
    def interval_ms(self) -> int:
        """Expose the public probe cadence to the shared timeline runner."""

        return self.probe_interval_ms


def fail(code: str, problem: str, cause: str) -> None:
    """Raise one structured fail-closed host-pressure error."""

    raise HostPressureError(
        code=code,
        problem=problem,
        cause=cause,
        impact="격리 VM pressure 실행을 중단하고 memory·stage 원상복구를 시도했습니다.",
        next_action="VM 상태, public probe, Control resource와 pressure timeline을 확인하십시오.",
    )


def _repository_path(root: Path, parent: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        fail(
            "PRESSURE_PROTECTION_MANIFEST_INVALID",
            "protection manifest는 상대 경로여야 합니다.",
            repr(value),
        )
    candidate = (parent / value).resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():
        fail(
            "PRESSURE_PROTECTION_MANIFEST_INVALID",
            "protection manifest 경계를 벗어났습니다.",
            str(candidate),
        )
    return candidate


def _certificate_path(value: object) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str):
        fail("PRESSURE_CA_INVALID", "CA certificate 경로가 올바르지 않습니다.", repr(value))
    path = Path(value)
    if not path.is_absolute() or path.name.endswith("-key.pem"):
        fail("PRESSURE_CA_INVALID", "공개 CA certificate 절대 경로만 허용합니다.", str(path))
    return path


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail("PRESSURE_MANIFEST_INVALID", f"{label} field가 정확하지 않습니다.", repr(value))
    return value


def _integer_between(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )
