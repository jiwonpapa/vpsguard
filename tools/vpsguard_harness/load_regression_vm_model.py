"""Validated NFR-001 private VM load-regression contracts and evidence helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import struct
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .load_regression import LoadBudgetResult, LoadMetrics, evaluate


class VmLoadRegressionError(HarnessError):
    """A private VM load proof violated a target, artifact or restore invariant."""


@dataclass(frozen=True)
class VmLoadRegressionManifest:
    """Exact 2GiB Nginx/PHP-FPM target and fixed 50 VU measurement contract."""

    host_alias: str
    domain: str
    guest_target: str
    private_ip: str
    stage_base: PurePosixPath
    host_stage_base: PurePosixPath
    target_memory_kib: int
    nginx_config: PurePosixPath
    nginx_service: str
    site_root: PurePosixPath
    php_fpm_socket: PurePosixPath
    request_host: str
    request_path: str
    direct_port: int
    edge_port: int
    worker_threads: int
    k6_version: str
    k6_sha256: str
    vus: int
    duration_seconds: int
    think_time_ms: int
    rounds: int

    @classmethod
    def load(cls, path: Path) -> "VmLoadRegressionManifest":
        """Load the exact schema and reject public, non-2GiB or weak workloads."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail("VM_LOAD_MANIFEST_READ_FAILED", "VM load manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "target",
            "runtime",
            "load",
        }:
            fail("VM_LOAD_MANIFEST_INVALID", "VM load manifest field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            fail(
                "VM_LOAD_SCHEMA_UNSUPPORTED",
                "VM load manifest schema를 지원하지 않습니다.",
                repr(raw["schema_version"]),
            )
        target = _exact_dict(
            raw["target"],
            {
                "host_alias",
                "domain",
                "guest_target",
                "private_ip",
                "stage_base",
                "host_stage_base",
                "target_memory_kib",
            },
            "target",
        )
        runtime = _exact_dict(
            raw["runtime"],
            {
                "nginx_config",
                "nginx_service",
                "site_root",
                "php_fpm_socket",
                "request_host",
                "request_path",
                "direct_port",
                "edge_port",
                "worker_threads",
            },
            "runtime",
        )
        load = _exact_dict(
            raw["load"],
            {
                "k6_version",
                "k6_sha256",
                "vus",
                "duration_seconds",
                "think_time_ms",
                "rounds",
            },
            "load",
        )
        guest_target = _private_guest_target(target["guest_target"], target["private_ip"])
        stage_base = _stage_base(target["stage_base"], guest_target)
        host_stage_base = _owned_stage_base(
            target["host_stage_base"],
            expected_user=target["host_alias"],
        )
        if target["target_memory_kib"] != 2_097_152:
            fail(
                "VM_LOAD_MEMORY_INVALID",
                "NFR-001 VM load는 정확히 2GiB libvirt target만 허용합니다.",
                repr(target["target_memory_kib"]),
            )
        nginx_config = _absolute_path(runtime["nginx_config"], "nginx config")
        if nginx_config != PurePosixPath("/" + "etc/nginx/conf.d/vpsguard-nfr001-origin.conf"):
            fail(
                "VM_LOAD_NGINX_PATH_INVALID",
                "NFR-001 임시 Nginx config는 전용 고정 경로만 허용합니다.",
                str(nginx_config),
            )
        site_root = _absolute_path(runtime["site_root"], "site root")
        php_fpm_socket = _absolute_path(runtime["php_fpm_socket"], "PHP-FPM socket")
        for value, label in (
            (target["host_alias"], "host alias"),
            (target["domain"], "domain"),
            (runtime["nginx_service"], "Nginx service"),
            (runtime["request_host"], "request Host"),
        ):
            _identifier(value, label)
        if (
            not isinstance(runtime["request_path"], str)
            or runtime["request_path"] != "/__vpsguard_nfr001"
        ):
            fail(
                "VM_LOAD_PATH_INVALID",
                "load request path는 전용 정적 Nginx fixture여야 합니다.",
                repr(runtime["request_path"]),
            )
        if (
            not _port(runtime["direct_port"])
            or not _port(runtime["edge_port"])
            or runtime["direct_port"] == runtime["edge_port"]
            or runtime["worker_threads"] != 2
        ):
            fail("VM_LOAD_RUNTIME_INVALID", "전용 port 또는 2-worker 계약이 올바르지 않습니다.", repr(runtime))
        if (
            load["k6_version"] != "0.55.2"
            or not isinstance(load["k6_sha256"], str)
            or len(load["k6_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in load["k6_sha256"])
            or load["vus"] != 50
            or load["duration_seconds"] != 15
            or load["think_time_ms"] != 100
            or load["rounds"] != 3
        ):
            fail("VM_LOAD_WORKLOAD_INVALID", "고정 k6 50 VU·15초·3회 계약이 올바르지 않습니다.", repr(load))
        return cls(
            host_alias=target["host_alias"],
            domain=target["domain"],
            guest_target=guest_target,
            private_ip=target["private_ip"],
            stage_base=stage_base,
            host_stage_base=host_stage_base,
            target_memory_kib=target["target_memory_kib"],
            nginx_config=nginx_config,
            nginx_service=runtime["nginx_service"],
            site_root=site_root,
            php_fpm_socket=php_fpm_socket,
            request_host=runtime["request_host"],
            request_path=runtime["request_path"],
            direct_port=runtime["direct_port"],
            edge_port=runtime["edge_port"],
            worker_threads=runtime["worker_threads"],
            k6_version=load["k6_version"],
            k6_sha256=load["k6_sha256"],
            vus=load["vus"],
            duration_seconds=load["duration_seconds"],
            think_time_ms=load["think_time_ms"],
            rounds=load["rounds"],
        )

    @property
    def confirmation(self) -> str:
        """Return the exact private VM execution confirmation."""

        return f"isolated-vm:{self.domain}"


@dataclass(frozen=True)
class VmLoadRound:
    """One paired direct-Nginx and guard-edge measurement."""

    number: int
    order: tuple[str, str]
    direct: LoadMetrics
    guard: LoadMetrics

    def as_dict(self) -> dict[str, object]:
        """Return a stable evidence representation."""

        return {
            "number": self.number,
            "order": list(self.order),
            "direct": asdict(self.direct),
            "guard": asdict(self.guard),
        }


def verify_k6_binary(path: Path, expected_sha256: str) -> str:
    """Require an x86_64 ELF artifact with the pinned SHA-256."""

    try:
        header = path.read_bytes()[:20]
    except OSError as error:
        fail("VM_LOAD_K6_READ_FAILED", "k6 binary를 읽지 못했습니다.", str(error))
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2:
        fail("VM_LOAD_K6_FORMAT_INVALID", "k6 binary가 ELF64가 아닙니다.", str(path))
    machine = struct.unpack("<H", header[18:20])[0]
    if header[5] != 1 or machine != 62:
        fail("VM_LOAD_K6_ARCH_INVALID", "k6 binary가 Linux x86_64 형식이 아닙니다.", str(path))
    digest = _sha256(path)
    if digest != expected_sha256:
        fail(
            "VM_LOAD_K6_CHECKSUM_MISMATCH",
            "k6 binary SHA-256이 manifest와 일치하지 않습니다.",
            f"actual={digest}",
        )
    return digest


def aggregate_rounds(rounds: list[VmLoadRound]) -> LoadBudgetResult:
    """Evaluate median p95/RPS while failing on any request error."""

    if len(rounds) != 3 or [item.number for item in rounds] != [1, 2, 3]:
        fail("VM_LOAD_ROUNDS_INVALID", "정확히 3개 paired round가 필요합니다.", repr(rounds))
    direct = LoadMetrics(
        p95_ms=_median([item.direct.p95_ms for item in rounds]),
        requests_per_second=_median([item.direct.requests_per_second for item in rounds]),
        failed_rate=max(item.direct.failed_rate for item in rounds),
    )
    guard = LoadMetrics(
        p95_ms=_median([item.guard.p95_ms for item in rounds]),
        requests_per_second=_median([item.guard.requests_per_second for item in rounds]),
        failed_rate=max(item.guard.failed_rate for item in rounds),
    )
    return evaluate(direct, guard)


def atomic_json(path: Path, value: dict[str, object]) -> None:
    """Atomically write one bounded, secret-free JSON artifact."""

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
    """Raise one structured fail-closed VM load error."""

    raise VmLoadRegressionError(
        code=code,
        problem=problem,
        cause=cause,
        impact="NFR-001 VM 측정을 중단하고 Nginx·memory·stage 원상복구를 시도했습니다.",
        next_action="격리 VM, artifact, listener와 복구 read-back을 확인하십시오.",
    )


def _private_guest_target(value: object, private_ip: object) -> str:
    if not isinstance(value, str) or value.count("@") != 1 or not isinstance(private_ip, str):
        fail("VM_LOAD_TARGET_INVALID", "guest target 형식이 올바르지 않습니다.", repr(value))
    user, address = value.split("@", maxsplit=1)
    _identifier(user, "guest user")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        fail("VM_LOAD_TARGET_INVALID", "guest IP가 올바르지 않습니다.", str(error))
    if not parsed.is_private or address != private_ip:
        fail(
            "VM_LOAD_TARGET_INVALID",
            "guest target은 manifest의 동일 private IP여야 합니다.",
            f"guest={address}, private_ip={private_ip}",
        )
    return value


def _stage_base(value: object, guest_target: str) -> PurePosixPath:
    if not isinstance(value, str):
        fail("VM_LOAD_STAGE_INVALID", "stage base가 문자열이 아닙니다.", repr(value))
    path = PurePosixPath(value)
    user = guest_target.split("@", maxsplit=1)[0]
    if (
        not path.is_absolute()
        or path.parts[:3] != ("/", "home", user)
        or path.name != "vpsguard-nfr001"
        or len(path.parts) != 4
    ):
        fail("VM_LOAD_STAGE_INVALID", "stage base가 전용 guest home 경로가 아닙니다.", str(path))
    return path


def _owned_stage_base(value: object, *, expected_user: object) -> PurePosixPath:
    if not isinstance(value, str) or not isinstance(expected_user, str):
        fail("VM_LOAD_STAGE_INVALID", "host stage base가 문자열이 아닙니다.", repr(value))
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.parts[:3] != ("/", "home", expected_user)
        or path.name != "vpsguard-nfr001"
        or len(path.parts) != 4
    ):
        fail("VM_LOAD_STAGE_INVALID", "host stage base가 SSH 계정 전용 home 경로가 아닙니다.", str(path))
    return path


def _absolute_path(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        fail("VM_LOAD_PATH_INVALID", f"{label}가 문자열이 아닙니다.", repr(value))
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        fail("VM_LOAD_PATH_INVALID", f"{label} 절대 경로가 올바르지 않습니다.", str(path))
    return path


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        fail("VM_LOAD_MANIFEST_INVALID", f"{label} field가 정확하지 않습니다.", repr(value))
    return value


def _identifier(value: object, label: str) -> None:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if not isinstance(value, str) or not value or len(value) > 128 or any(c not in allowed for c in value):
        fail("VM_LOAD_IDENTIFIER_INVALID", f"{label} 형식이 올바르지 않습니다.", repr(value))


def _port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1_024 <= value <= 65_535


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1_024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _median(values: list[float]) -> float:
    if len(values) != 3 or any(not math.isfinite(value) for value in values):
        fail("VM_LOAD_METRICS_INVALID", "median 입력 metric이 올바르지 않습니다.", repr(values))
    return sorted(values)[1]
