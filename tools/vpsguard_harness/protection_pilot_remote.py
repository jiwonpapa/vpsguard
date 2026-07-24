"""Remote staging, libvirt memory and read-back helpers for the UI-018 pilot."""

from __future__ import annotations

import json
import re
import shlex
import time
from pathlib import Path, PurePosixPath

from .protection_pilot_model import Bundle, ProtectionPilotManifest, fail
from .qga import GuestAgent, GuestCommandResult
from .runner import CommandResult, CommandRunner, CommandScope, CommandSpec


def stage(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    bundle: Bundle,
    stage_path: PurePosixPath,
) -> None:
    """Copy only the verified bundle and body-free probe into a fresh stage."""

    exists = ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/test", "!", "-e", str(stage_path)),
        label="pilot stage must not exist",
    )
    if exists.exit_code != 0:
        fail("PILOT_STAGE_EXISTS", "pilot stage가 이미 존재합니다.", str(stage_path))
    ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/mkdir", "-p", f"{stage_path}/bundle"),
        label="create pilot stage",
    )
    runner.run(
        CommandSpec(
            label="copy verified release bundle",
            argv=(
                "rsync",
                "-a",
                f"{bundle.path}/",
                f"{manifest.guest_copy_target}:{stage_path}/bundle/",
            ),
            cwd=root,
            timeout_seconds=120,
            scope=CommandScope.TEST,
        )
    )
    runner.run(
        CommandSpec(
            label="copy protection settings probe",
            argv=(
                "rsync",
                "-a",
                str(root / "tools/vm/protection-settings-probe.py"),
                f"{manifest.guest_copy_target}:{stage_path}/",
            ),
            cwd=root,
            timeout_seconds=30,
            scope=CommandScope.TEST,
        )
    )


def remove_stage(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    stage_path: PurePosixPath,
) -> None:
    """Remove only the validated per-commit guest-user stage."""

    ssh(
        runner,
        root,
        manifest.guest_copy_target,
        ("/bin/rm", "-rf", "--", str(stage_path)),
        label="remove restored pilot stage",
    )


def domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
) -> int:
    """Read the live libvirt memory target in KiB."""

    output = host_virsh(
        runner,
        root,
        manifest,
        ("dominfo", manifest.domain),
        label="read domain memory",
    )
    match = re.search(r"^Used memory:\s+(\d+)\s+KiB$", output, flags=re.MULTILINE)
    if match is None:
        fail("PILOT_DOMAIN_MEMORY_INVALID", "libvirt memory read-back을 해석하지 못했습니다.", output)
    return int(match.group(1))


def set_domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    memory_kib: int,
) -> None:
    """Set and read back one live libvirt memory target."""

    host_virsh(
        runner,
        root,
        manifest,
        ("setmem", manifest.domain, str(memory_kib), "--live"),
        label="set domain memory",
    )
    if not wait_domain_memory(runner, root, manifest, memory_kib):
        fail(
            "PILOT_DOMAIN_MEMORY_READBACK_FAILED",
            "libvirt memory target read-back이 일치하지 않습니다.",
            f"expected={memory_kib}",
        )


def wait_domain_memory(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    expected_kib: int,
) -> bool:
    """Poll bounded libvirt memory read-back."""

    for _attempt in range(20):
        if domain_memory(runner, root, manifest) == expected_kib:
            return True
        time.sleep(0.25)
    return False


def wait_guest_memory(guest: GuestAgent, target_kib: int) -> int:
    """Require the guest kernel MemTotal to reflect the 2GiB balloon."""

    lower_bound = int(target_kib * 0.80)
    for _attempt in range(30):
        output = guest.execute(("/bin/cat", "/proc/meminfo")).stdout
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB$", output, flags=re.MULTILINE)
        if match is not None:
            value = int(match.group(1))
            if lower_bound <= value <= target_kib:
                return value
        time.sleep(0.5)
    fail(
        "PILOT_GUEST_MEMORY_READBACK_FAILED",
        "guest MemTotal이 2GiB target 범위에 도달하지 않았습니다.",
        f"target={target_kib}",
    )


def service_states(guest: GuestAgent, services: tuple[str, ...]) -> dict[str, str]:
    """Read and require active state for the bounded service allowlist."""

    states = {}
    for service in services:
        result = guest.execute(("/bin/systemctl", "is-active", service))
        states[service] = result.stdout.strip()
        if states[service] != "active":
            fail(
                "PILOT_SERVICE_INACTIVE",
                "검증 service가 active가 아닙니다.",
                f"{service}={states[service]}",
            )
    return states


def snapshot_path(output: str) -> str:
    """Extract the update script's final rollback snapshot."""

    matches = re.findall(r"snapshot=(/\S+)", output)
    if not matches:
        fail("PILOT_SNAPSHOT_MISSING", "update rollback snapshot을 찾지 못했습니다.", output)
    return matches[-1]


def probe_json(output: str) -> dict[str, object]:
    """Parse the sanitized standalone policy probe result."""

    try:
        value = json.loads(output.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        fail("PILOT_PROBE_OUTPUT_INVALID", "policy probe JSON을 해석하지 못했습니다.", str(error))
    if (
        not isinstance(value, dict)
        or value.get("result") != "PASS"
        or value.get("original_settings_restored") is not True
        or value.get("edge_readback") != "observed"
    ):
        fail("PILOT_PROBE_FAILED", "policy probe 불변조건이 통과하지 못했습니다.", repr(value))
    return value


def guest_text(result: GuestCommandResult, label: str) -> str:
    """Return one bounded single-line guest value."""

    value = result.stdout.strip()
    if not value or "\n" in value:
        fail("PILOT_GUEST_VALUE_INVALID", f"{label} read-back이 올바르지 않습니다.", repr(value))
    return value


def ssh(
    runner: CommandRunner,
    root: Path,
    target: str,
    remote_argv: tuple[str, ...],
    *,
    label: str,
) -> CommandResult:
    """Execute one strictly quoted guest-user SSH command."""

    return runner.run(
        CommandSpec(
            label=label,
            argv=("ssh", "-o", "BatchMode=yes", target, shlex.join(remote_argv)),
            cwd=root,
            timeout_seconds=30,
            scope=CommandScope.TEST,
            accepted_exit_codes=(0, 1)
            if remote_argv[:3] == ("/bin/test", "!", "-e")
            else (0,),
        )
    )


def host_virsh(
    runner: CommandRunner,
    root: Path,
    manifest: ProtectionPilotManifest,
    arguments: tuple[str, ...],
    *,
    label: str,
) -> str:
    """Execute one allowlisted virsh argv through the lab host."""

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
