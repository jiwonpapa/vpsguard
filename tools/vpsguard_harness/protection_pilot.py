"""UI-018 isolated 2GB VM update, policy read-back and automatic restore pilot."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .qga import GuestAgent, GuestCommandResult
from .runner import CommandRunner, CommandScope, CommandSpec


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
            _raise("PILOT_MANIFEST_READ_FAILED", "pilot manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "target",
            "runtime",
            "management",
        }:
            _raise("PILOT_MANIFEST_INVALID", "pilot manifest 최상위 field가 정확하지 않습니다.", repr(raw))
        if raw["schema_version"] != 1:
            _raise("PILOT_SCHEMA_UNSUPPORTED", "pilot manifest schema를 지원하지 않습니다.", repr(raw["schema_version"]))
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
            _raise(
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
            _raise("PILOT_SERVICES_INVALID", "검증 service 목록이 올바르지 않습니다.", repr(services))
        if target["target_memory_kib"] != 2_097_152:
            _raise(
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
                _raise("PILOT_PATH_INVALID", f"{label} 절대 경로가 올바르지 않습니다.", repr(value))
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
        build_info = path / "BUILD-INFO.txt"
        checksums = path / "SHA256SUMS"
        try:
            info = build_info.read_text(encoding="utf-8").splitlines()
            entries = checksums.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            _raise("PILOT_BUNDLE_READ_FAILED", "release bundle metadata를 읽지 못했습니다.", str(error))
        if (
            "target=x86_64-unknown-linux-gnu" not in info
            or not info
            or re.fullmatch(r"[0-9a-f]{40}", info[-1]) is None
        ):
            _raise("PILOT_BUNDLE_IDENTITY_INVALID", "x86_64 bundle identity가 올바르지 않습니다.", str(path))
        if not 1 <= len(entries) <= 4_096:
            _raise("PILOT_CHECKSUMS_INVALID", "bundle checksum 개수가 올바르지 않습니다.", str(len(entries)))
        for entry in entries:
            match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", entry)
            if match is None:
                _raise("PILOT_CHECKSUMS_INVALID", "bundle checksum line이 올바르지 않습니다.", entry)
            candidate = (path / match.group(2)).resolve()
            if not candidate.is_relative_to(path) or not candidate.is_file():
                _raise("PILOT_BUNDLE_ESCAPE", "bundle checksum path가 경계를 벗어났습니다.", str(candidate))
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if digest != match.group(1):
                _raise("PILOT_CHECKSUM_MISMATCH", "bundle checksum이 일치하지 않습니다.", match.group(2))
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
    policy: dict[str, object]
    services_before: dict[str, str]
    services_after: dict[str, str]
    elapsed_ms: int

    def as_dict(self) -> dict[str, object]:
        """Return the stable JSON evidence shape."""

        return {
            "schema_version": 1,
            "result": "PASS",
            "source_commit": self.source_commit,
            "original_release": self.original_release,
            "candidate_release": self.candidate_release,
            "restored_release": self.restored_release,
            "original_memory_kib": self.original_memory_kib,
            "target_memory_kib": self.target_memory_kib,
            "guest_mem_total_kib": self.guest_mem_total_kib,
            "policy": self.policy,
            "services_before": self.services_before,
            "services_after": self.services_after,
            "elapsed_ms": self.elapsed_ms,
            "original_release_restored": self.original_release == self.restored_release,
            "original_memory_restored": True,
            "stores_credentials": False,
            "stores_request_bodies": False,
        }


def run_protection_pilot(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> ProtectionPilotSummary | None:
    """Plan or execute the isolated update, 2GB policy proof and full restore."""

    manifest = ProtectionPilotManifest.load(manifest_path)
    bundle = Bundle.verify(bundle_path)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        _raise("PILOT_EVIDENCE_ESCAPE", "pilot evidence는 repository 아래여야 합니다.", str(evidence_path))
    stage = manifest.stage_base / bundle.source_commit
    plan = {
        "schema_version": 1,
        "target": {
            "host_alias": manifest.host_alias,
            "domain": manifest.domain,
            "guest_copy_target": manifest.guest_copy_target,
            "target_memory_kib": manifest.target_memory_kib,
        },
        "source_commit": bundle.source_commit,
        "stage": str(stage),
        "steps": [
            "verify_bundle",
            "capture_release_memory_services",
            "stage_bundle_and_probe",
            "update_with_snapshot_rollback",
            "balloon_to_2gib",
            "authenticated_policy_plan_apply_edge_readback_restore",
            "restore_deployment_snapshot",
            "restore_original_memory",
            "verify_release_and_services",
        ],
        "confirmation": manifest.confirmation,
        "preserves": ["SSH", "Apache", "certificate", "site data", "original VPSGuard state"],
        "stores_credentials": False,
        "stores_request_bodies": False,
    }
    _atomic_json(evidence_path.with_suffix(".plan.json"), plan)
    if not execute:
        return None
    if confirmation != manifest.confirmation:
        _raise(
            "PILOT_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.host_alias,
        domain=manifest.domain,
    )
    guest.ping()
    original_release = _guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
        "original release",
    )
    original_memory = _domain_memory(runner, root, manifest)
    if original_memory < manifest.target_memory_kib:
        _raise(
            "PILOT_MEMORY_UNDERSIZED",
            "현재 VM memory가 pilot target보다 작습니다.",
            f"current={original_memory}, target={manifest.target_memory_kib}",
        )
    services_before = _service_states(guest, manifest.services)
    started = time.monotonic_ns()
    snapshot: str | None = None
    candidate_release = ""
    guest_mem_total = 0
    policy: dict[str, object] = {}
    restored = False
    memory_restored = False
    try:
        _stage(runner, root, manifest, bundle, stage)
        update = guest.execute(
            (
                "/bin/bash",
                f"{stage}/bundle/scripts/update-release.sh",
                "--apply",
                f"{stage}/bundle",
            ),
            environment=(
                "LANG=C",
                "VPS_GUARD_UPDATE_CONFIRM=update-with-rollback",
                f"VPS_GUARD_EDGE_HOST={manifest.edge_host}",
            ),
            timeout_seconds=120,
        )
        snapshot = _snapshot_path(update.stdout)
        candidate_release = _guest_text(
            guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
            "candidate release",
        )
        if not candidate_release.endswith(f"/{bundle.source_commit}"):
            _raise(
                "PILOT_RELEASE_READBACK_MISMATCH",
                "candidate release symlink가 source commit과 일치하지 않습니다.",
                candidate_release,
            )
        _set_domain_memory(runner, root, manifest, manifest.target_memory_kib)
        guest_mem_total = _wait_guest_memory(guest, manifest.target_memory_kib)
        probe = guest.execute(
            (
                "/bin/python3",
                f"{stage}/protection-settings-probe.py",
                "--control-url",
                manifest.control_url,
                "--edge-url",
                manifest.edge_url,
                "--management-host",
                manifest.management_host,
                "--management-origin",
                manifest.management_origin,
                "--edge-host",
                manifest.edge_host,
                "--admin-socket",
                manifest.admin_socket,
            ),
            timeout_seconds=90,
        )
        policy = _probe_json(probe.stdout)
    finally:
        if snapshot is not None:
            try:
                guest.execute(
                    (
                        "/bin/bash",
                        f"{stage}/bundle/scripts/deployment-state.sh",
                        "--restore",
                        snapshot,
                    ),
                    environment=(
                        "LANG=C",
                        "VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot",
                    ),
                    timeout_seconds=120,
                )
                restored = True
            except HarnessError:
                restored = False
        try:
            _set_domain_memory(runner, root, manifest, original_memory)
            memory_restored = _wait_domain_memory(
                runner,
                root,
                manifest,
                original_memory,
            )
        except HarnessError:
            memory_restored = False
        if restored and memory_restored:
            _remove_stage(runner, root, manifest, stage)
    if not restored or not memory_restored:
        _raise(
            "PILOT_AUTOMATIC_RESTORE_FAILED",
            "pilot 종료 복구를 완료하지 못했습니다.",
            f"deployment_restored={restored}, memory_restored={memory_restored}, stage={stage}",
        )
    restored_release = _guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
        "restored release",
    )
    services_after = _service_states(guest, manifest.services)
    if restored_release != original_release or services_after != services_before:
        _raise(
            "PILOT_PRESERVATION_MISMATCH",
            "pilot 종료 상태가 시작 상태와 일치하지 않습니다.",
            f"release_match={restored_release == original_release}, services_match={services_after == services_before}",
        )
    summary = ProtectionPilotSummary(
        source_commit=bundle.source_commit,
        original_release=original_release,
        candidate_release=candidate_release,
        restored_release=restored_release,
        original_memory_kib=original_memory,
        target_memory_kib=manifest.target_memory_kib,
        guest_mem_total_kib=guest_mem_total,
        policy=policy,
        services_before=services_before,
        services_after=services_after,
        elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
    )
    _atomic_json(evidence_path, summary.as_dict())
    return summary


def _stage(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    bundle: Bundle,
    stage: PurePosixPath,
) -> None:
    exists = _ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/test", "!", "-e", str(stage)),
        label="pilot stage must not exist",
    )
    if exists.exit_code != 0:
        _raise("PILOT_STAGE_EXISTS", "pilot stage가 이미 존재합니다.", str(stage))
    _ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/mkdir", "-p", f"{stage}/bundle"),
        label="create pilot stage",
    )
    runner.run(
        CommandSpec(
            label="copy verified release bundle",
            argv=("rsync", "-a", f"{bundle.path}/", f"{manifest.guest_copy_target}:{stage}/bundle/"),
            cwd=root,
            timeout_seconds=120,
            scope=CommandScope.TEST,
        )
    )
    probe = root / "tools/vm/protection-settings-probe.py"
    runner.run(
        CommandSpec(
            label="copy protection settings probe",
            argv=("rsync", "-a", str(probe), f"{manifest.guest_copy_target}:{stage}/"),
            cwd=root,
            timeout_seconds=30,
            scope=CommandScope.TEST,
        )
    )


def _remove_stage(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    stage: PurePosixPath,
) -> None:
    _ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/rm", "-rf", "--", str(stage)),
        label="remove restored pilot stage",
    )


def _ssh(
    runner: CommandRunner,
    root: Path,
    target: str,
    remote_argv: tuple[str, ...],
    *,
    label: str,
) -> object:
    return runner.run(
        CommandSpec(
            label=label,
            argv=("ssh", "-o", "BatchMode=yes", target, shlex.join(remote_argv)),
            cwd=root,
            timeout_seconds=30,
            scope=CommandScope.TEST,
            accepted_exit_codes=(0, 1) if remote_argv[:3] == ("/bin/test", "!", "-e") else (0,),
        )
    )


def _host_virsh(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    arguments: tuple[str, ...],
    *,
    label: str,
) -> str:
    remote = shlex.join(("virsh", "-c", "qemu:///system", *arguments))
    result = runner.run(
        CommandSpec(
            label=label,
            argv=("ssh", "-o", "BatchMode=yes", manifest.host_alias, remote),
            cwd=root,
            timeout_seconds=30,
            scope=CommandScope.TEST,
        )
    )
    return result.stdout


def _domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
) -> int:
    output = _host_virsh(
        runner,
        root,
        manifest,
        ("dominfo", manifest.domain),
        label="read domain memory",
    )
    match = re.search(r"^Used memory:\s+(\d+)\s+KiB$", output, flags=re.MULTILINE)
    if match is None:
        _raise("PILOT_DOMAIN_MEMORY_INVALID", "libvirt memory read-back을 해석하지 못했습니다.", output)
    return int(match.group(1))


def _set_domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    memory_kib: int,
) -> None:
    _host_virsh(
        runner,
        root,
        manifest,
        ("setmem", manifest.domain, str(memory_kib), "--live"),
        label="set domain memory",
    )
    if not _wait_domain_memory(runner, root, manifest, memory_kib):
        _raise(
            "PILOT_DOMAIN_MEMORY_READBACK_FAILED",
            "libvirt memory target read-back이 일치하지 않습니다.",
            f"expected={memory_kib}",
        )


def _wait_domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    expected_kib: int,
) -> bool:
    for _attempt in range(20):
        if _domain_memory(runner, root, manifest) == expected_kib:
            return True
        time.sleep(0.25)
    return False


def _wait_guest_memory(guest: GuestAgent, target_kib: int) -> int:
    lower_bound = int(target_kib * 0.80)
    for _attempt in range(30):
        output = guest.execute(("/bin/cat", "/proc/meminfo")).stdout
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB$", output, flags=re.MULTILINE)
        if match is not None:
            value = int(match.group(1))
            if lower_bound <= value <= target_kib:
                return value
        time.sleep(0.5)
    _raise(
        "PILOT_GUEST_MEMORY_READBACK_FAILED",
        "guest MemTotal이 2GiB target 범위에 도달하지 않았습니다.",
        f"target={target_kib}",
    )


def _service_states(guest: GuestAgent, services: tuple[str, ...]) -> dict[str, str]:
    states = {}
    for service in services:
        result = guest.execute(("/bin/systemctl", "is-active", service))
        states[service] = result.stdout.strip()
        if states[service] != "active":
            _raise("PILOT_SERVICE_INACTIVE", "검증 service가 active가 아닙니다.", f"{service}={states[service]}")
    return states


def _snapshot_path(output: str) -> str:
    matches = re.findall(r"snapshot=(/\S+)", output)
    if not matches:
        _raise("PILOT_SNAPSHOT_MISSING", "update rollback snapshot을 찾지 못했습니다.", output)
    return matches[-1]


def _probe_json(output: str) -> dict[str, object]:
    try:
        value = json.loads(output.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        _raise("PILOT_PROBE_OUTPUT_INVALID", "policy probe JSON을 해석하지 못했습니다.", str(error))
    if (
        not isinstance(value, dict)
        or value.get("result") != "PASS"
        or value.get("original_settings_restored") is not True
        or value.get("edge_readback") != "observed"
    ):
        _raise("PILOT_PROBE_FAILED", "policy probe 불변조건이 통과하지 못했습니다.", repr(value))
    return value


def _guest_text(result: GuestCommandResult, label: str) -> str:
    value = result.stdout.strip()
    if not value or "\n" in value:
        _raise("PILOT_GUEST_VALUE_INVALID", f"{label} read-back이 올바르지 않습니다.", repr(value))
    return value


def _private_ssh_target(value: object) -> str:
    if not isinstance(value, str) or value.count("@") != 1:
        _raise("PILOT_GUEST_TARGET_INVALID", "guest SSH target이 올바르지 않습니다.", repr(value))
    user, host = value.split("@", maxsplit=1)
    _bounded_text(user, "guest user")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        _raise("PILOT_GUEST_TARGET_INVALID", "guest SSH target IP가 올바르지 않습니다.", str(error))
    if not address.is_private:
        _raise("PILOT_GUEST_TARGET_PUBLIC", "public guest target은 허용하지 않습니다.", str(address))
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
        _raise("PILOT_TEXT_INVALID", f"{label} 값이 올바르지 않습니다.", repr(value))
    return value


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        _raise("PILOT_MANIFEST_INVALID", f"{label} field가 정확하지 않습니다.", repr(value))
    return value


def _atomic_json(path: Path, value: dict[str, object]) -> None:
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


def _raise(code: str, problem: str, cause: str) -> None:
    raise ProtectionPilotError(
        code=code,
        problem=problem,
        cause=cause,
        impact="격리 VM pilot 다음 단계를 중단하고 가능한 자동 복구를 수행했습니다.",
        next_action="남은 stage와 snapshot을 보존한 채 release·memory·service 상태를 확인하십시오.",
    )
