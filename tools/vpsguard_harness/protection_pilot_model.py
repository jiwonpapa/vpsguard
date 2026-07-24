"""Validated manifest, bundle identity and sanitized UI-018 pilot evidence models."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import HarnessError


class ProtectionPilotError(HarnessError):
    """The isolated VM pilot violated a preservation or read-back invariant."""


@dataclass(frozen=True)
class ProtectionPilotManifest:
    """Strict private VM, staging, service and Control endpoint contract."""

    host_alias: str
    domain: str
    guest_copy_target: str
    stage_base: PurePosixPath
    target_memory_kib: int
    current_release_path: str
    services: tuple[str, ...]
    control_url: str
    management_host: str
    management_origin: str
    admin_socket: str
    edge_url: str
    edge_host: str

    @classmethod
    def load(cls, path: Path) -> "ProtectionPilotManifest":
        """Load an exact schema and reject public or non-2GB targets."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail("PILOT_MANIFEST_READ_FAILED", "pilot manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "target",
            "runtime",
            "management",
        }:
            fail("PILOT_MANIFEST_INVALID", "pilot manifest 최상위 field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            fail(
                "PILOT_SCHEMA_UNSUPPORTED",
                "pilot manifest schema를 지원하지 않습니다.",
                repr(raw["schema_version"]),
            )
        target = _exact_dict(
            raw["target"],
            {"host_alias", "domain", "guest_copy_target", "stage_base", "target_memory_kib"},
            "target",
        )
        runtime = _exact_dict(
            raw["runtime"],
            {"current_release_path", "services"},
            "runtime",
        )
        management = _exact_dict(
            raw["management"],
            {
                "control_url",
                "management_host",
                "management_origin",
                "admin_socket",
                "edge_url",
                "edge_host",
            },
            "management",
        )
        guest_target = _private_ssh_target(target["guest_copy_target"])
        stage_base = PurePosixPath(target["stage_base"])
        guest_user = guest_target.split("@", maxsplit=1)[0]
        if (
            not stage_base.is_absolute()
            or stage_base.parts[:3] != ("/", "home", guest_user)
            or not stage_base.name.startswith("vpsguard-")
            or len(stage_base.parts) != 4
        ):
            fail(
                "PILOT_STAGE_INVALID",
                "pilot stage는 guest 사용자 home 바로 아래 VPSGuard 전용 경로여야 합니다.",
                str(stage_base),
            )
        services = runtime["services"]
        if (
            not isinstance(services, list)
            or not services
            or len(services) > 8
            or any(not _service_name(value) for value in services)
        ):
            fail("PILOT_SERVICES_INVALID", "검증 service 목록이 올바르지 않습니다.", repr(services))
        if target["target_memory_kib"] != 2_097_152:
            fail(
                "PILOT_MEMORY_INVALID",
                "UI-018 pilot은 정확히 2GiB libvirt target만 허용합니다.",
                repr(target["target_memory_kib"]),
            )
        for value, label in (
            (target["host_alias"], "host alias"),
            (target["domain"], "domain"),
            (management["management_host"], "management host"),
            (management["edge_host"], "edge host"),
        ):
            _bounded_text(value, label)
        for value, label in (
            (runtime["current_release_path"], "current release path"),
            (management["admin_socket"], "admin socket"),
        ):
            if not isinstance(value, str) or not PurePosixPath(value).is_absolute():
                fail("PILOT_PATH_INVALID", f"{label} 절대 경로가 올바르지 않습니다.", repr(value))
        return cls(
            host_alias=target["host_alias"],
            domain=target["domain"],
            guest_copy_target=guest_target,
            stage_base=stage_base,
            target_memory_kib=target["target_memory_kib"],
            current_release_path=runtime["current_release_path"],
            services=tuple(services),
            control_url=management["control_url"],
            management_host=management["management_host"],
            management_origin=management["management_origin"],
            admin_socket=management["admin_socket"],
            edge_url=management["edge_url"],
            edge_host=management["edge_host"],
        )

    @property
    def confirmation(self) -> str:
        """Return the exact execution confirmation token."""

        return f"isolated-vm:{self.domain}"


@dataclass(frozen=True)
class Bundle:
    """Locally verified x86_64 release bundle identity."""

    path: Path
    source_commit: str

    @classmethod
    def verify(cls, path: Path) -> "Bundle":
        """Verify every checksum and the exact Linux architecture metadata."""

        path = path.resolve()
        try:
            info = (path / "BUILD-INFO.txt").read_text(encoding="utf-8").splitlines()
            entries = (path / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        except OSError as error:
            fail("PILOT_BUNDLE_READ_FAILED", "release bundle metadata를 읽지 못했습니다.", str(error))
        if (
            "target=x86_64-unknown-linux-gnu" not in info
            or not info
            or re.fullmatch(r"[0-9a-f]{40}", info[-1]) is None
        ):
            fail("PILOT_BUNDLE_IDENTITY_INVALID", "x86_64 bundle identity가 올바르지 않습니다.", str(path))
        if not 1 <= len(entries) <= 4_096:
            fail("PILOT_CHECKSUMS_INVALID", "bundle checksum 개수가 올바르지 않습니다.", str(len(entries)))
        for entry in entries:
            match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", entry)
            if match is None:
                fail("PILOT_CHECKSUMS_INVALID", "bundle checksum line이 올바르지 않습니다.", entry)
            candidate = (path / match.group(2)).resolve()
            if not candidate.is_relative_to(path) or not candidate.is_file():
                fail("PILOT_BUNDLE_ESCAPE", "bundle checksum path가 경계를 벗어났습니다.", str(candidate))
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != match.group(1):
                fail("PILOT_CHECKSUM_MISMATCH", "bundle checksum이 일치하지 않습니다.", match.group(2))
        return cls(path=path, source_commit=info[-1])


@dataclass(frozen=True)
class ProtectionPilotSummary:
    """Sanitized pilot evidence with no session or request body material."""

    source_commit: str
    original_release: str
    candidate_release: str
    restored_release: str
    original_memory_kib: int
    target_memory_kib: int
    guest_mem_total_kib: int
    balloon_driver_was_loaded: bool
    balloon_driver_restored: bool
    policy: dict[str, object]
    services_before: dict[str, str]
    services_after: dict[str, str]
    elapsed_ms: int

    def as_dict(self) -> dict[str, object]:
        """Return the stable JSON evidence shape."""

        return {
            "schema_version": 1,
            "result": "PASS",
            **self.__dict__,
            "original_release_restored": self.original_release == self.restored_release,
            "original_memory_restored": True,
            "stores_credentials": False,
            "stores_request_bodies": False,
        }


def atomic_json(path: Path, value: dict[str, object]) -> None:
    """Atomically persist one sanitized plan or evidence object."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        prefix=f".{path.name}.",
        dir=path.parent,
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
    temporary.replace(path)


def fail(code: str, problem: str, cause: str) -> None:
    """Raise one structured fail-closed pilot error."""

    raise ProtectionPilotError(
        code=code,
        problem=problem,
        cause=cause,
        impact="격리 VM pilot 다음 단계를 중단하고 가능한 자동 복구를 수행했습니다.",
        next_action="남은 stage와 snapshot을 보존한 채 release·memory·service 상태를 확인하십시오.",
    )


def _private_ssh_target(value: object) -> str:
    if not isinstance(value, str) or value.count("@") != 1:
        fail("PILOT_GUEST_TARGET_INVALID", "guest SSH target이 올바르지 않습니다.", repr(value))
    user, host = value.split("@", maxsplit=1)
    _bounded_text(user, "guest user")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        fail("PILOT_GUEST_TARGET_INVALID", "guest SSH target IP가 올바르지 않습니다.", str(error))
    if not address.is_private:
        fail("PILOT_GUEST_TARGET_PUBLIC", "public guest target은 허용하지 않습니다.", str(address))
    return f"{user}@{address}"


def _service_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value.endswith((".service", ".socket"))
        and all(character.isalnum() or character in "._@-" for character in value)
    )


def _bounded_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(control in value for control in "\x00\r\n")
    ):
        fail("PILOT_TEXT_INVALID", f"{label} 값이 올바르지 않습니다.", repr(value))
    return value


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail("PILOT_MANIFEST_INVALID", f"{label} field가 정확하지 않습니다.", repr(value))
    return value
