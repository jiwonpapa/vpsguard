"""Remote stage and exact restoration helpers for DET-014 pressure proof."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .host_pressure_model import HostPressureManifest, fail
from .protection_pilot_model import Bundle
from .protection_pilot_remote import (
    balloon_driver_loaded,
    restore_balloon_driver,
    set_domain_memory,
    ssh,
    wait_domain_memory,
    wait_guest_memory,
)
from .qga import GuestAgent
from .runner import CommandRunner, CommandScope, CommandSpec


def stage_pressure_probe(
    runner: CommandRunner,
    root: Path,
    manifest: HostPressureManifest,
    bundle: Bundle,
    stage_path: PurePosixPath,
) -> None:
    """Copy only one verified bundle and the two fixed pressure scripts."""

    exists = ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/test", "!", "-e", str(stage_path)),
        label="pressure stage must not exist",
    )
    if exists.exit_code != 0:
        fail("PRESSURE_STAGE_EXISTS", "pressure stage가 이미 존재합니다.", str(stage_path))
    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/mkdir", "-p", f"{stage_path}/bundle"),
        label="create pressure stage",
    )
    runner.run(
        CommandSpec(
            label="copy verified pressure release bundle",
            argv=(
                "rsync",
                "-a",
                f"{bundle.path}/",
                f"{manifest.protection.guest_copy_target}:{stage_path}/bundle/",
            ),
            cwd=root,
            timeout_seconds=120,
            scope=CommandScope.TEST,
        )
    )
    for name in ("host-pressure-probe.py", "host_pressure_support.py"):
        runner.run(
            CommandSpec(
                label=f"copy pressure probe {name}",
                argv=(
                    "rsync",
                    "-a",
                    str(root / "tools/vm" / name),
                    f"{manifest.protection.guest_copy_target}:{stage_path}/",
                ),
                cwd=root,
                timeout_seconds=30,
                scope=CommandScope.TEST,
            )
        )


def restore_pressure_memory(
    runner: CommandRunner,
    guest: GuestAgent,
    root: Path,
    manifest: HostPressureManifest,
    original_memory: int,
    balloon_was_loaded: bool,
) -> tuple[bool, bool]:
    """Restore exact libvirt memory and pre-run balloon module ownership."""

    try:
        set_domain_memory(
            runner,
            root,
            manifest.protection,
            original_memory,
        )
        memory_restored = wait_domain_memory(
            runner,
            root,
            manifest.protection,
            original_memory,
        )
    except HarnessError:
        memory_restored = False
    try:
        if memory_restored and not balloon_was_loaded and balloon_driver_loaded(guest):
            wait_guest_memory(guest, original_memory)
        balloon_restored = restore_balloon_driver(
            guest,
            was_loaded=balloon_was_loaded,
        )
    except HarnessError:
        balloon_restored = False
    return memory_restored, balloon_restored


def require_pressure_restored(
    original_release: str,
    restored_release: str,
    services_before: dict[str, str],
    services_after: dict[str, str],
    deployment_restored: bool,
    memory_restored: bool,
    balloon_restored: bool,
) -> None:
    """Require exact release, service, deployment, memory and module restoration."""

    if (
        original_release != restored_release
        or services_before != services_after
        or not deployment_restored
        or not memory_restored
        or not balloon_restored
    ):
        fail(
            "PRESSURE_AUTOMATIC_RESTORE_FAILED",
            "pressure 종료 원상복구가 시작 상태와 일치하지 않습니다.",
            (
                f"release_match={original_release == restored_release}, "
                f"services_match={services_before == services_after}, "
                f"deployment_restored={deployment_restored}, "
                f"memory_restored={memory_restored}, "
                f"balloon_restored={balloon_restored}"
            ),
        )


def remove_pressure_stage(
    guest: GuestAgent,
    stage_path: PurePosixPath,
) -> None:
    """Remove only a validated source-commit stage through root guest agent."""

    guest.execute(pressure_cleanup_command(stage_path))


def pressure_cleanup_command(stage_path: PurePosixPath) -> tuple[str, ...]:
    """Build the exact root cleanup command for one DET-014 commit stage."""

    commit = stage_path.name
    if (
        stage_path.parent.name != "det014-host-pressure"
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        fail(
            "PRESSURE_STAGE_UNSAFE",
            "pressure stage 정리 경로가 commit 경계와 일치하지 않습니다.",
            str(stage_path),
        )
    return ("/bin/rm", "-rf", "--", str(stage_path))
