"""Bounded root guest operations and exact restore for TLS reload proof."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path, PurePosixPath

from .protection_pilot_model import Bundle
from .protection_pilot_remote import (
    guest_text,
    restore_balloon_driver,
    set_domain_memory,
    ssh,
    wait_domain_memory,
)
from .qga import GuestAgent
from .runner import CommandRunner, CommandScope, CommandSpec
from .tls_reload_model import TlsReloadManifest, fail

TEST_SERVICE = "vps-guard-tls-probe.service"
TEST_UNIT = f"/run/systemd/system/{TEST_SERVICE}"
TEST_INSTALL = "/opt/vps-guard-tls-probe"
TEST_RUNTIME = "/run/vps-guard-tls-probe"
RELOAD_RUNTIME = "/run/vps-guard-tls"
UPGRADE_SOCKET = "/run/vps-guard/pingora-upgrade.sock"


def stage_reload_command(manifest: TlsReloadManifest) -> tuple[str, ...]:
    """Return the exact root CLI command for the renewed PEM fixture."""

    return (
        f"{TEST_INSTALL}/vps-guard",
        "stage-tls-reload",
        "--certificate",
        f"{TEST_INSTALL}/next/fullchain.pem",
        "--key",
        f"{TEST_INSTALL}/next/privkey.pem",
        "--server-name",
        manifest.probe_host,
    )


def stage_fixture(
    runner: CommandRunner,
    root: Path,
    manifest: TlsReloadManifest,
    bundle: Bundle,
    stage_path: PurePosixPath,
    fixture: Path,
) -> None:
    """Copy only verified binaries, config, unit and ephemeral PEM fixtures."""

    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/mkdir", "-p", str(stage_path)),
        label="create TLS reload stage",
    )
    sources = (
        bundle.path / "bin/vps-guard",
        bundle.path / "bin/vps-guard-edge",
        root / "tools/vm/tls-reload-config.toml",
        root / "tools/vm/vps-guard-tls-probe.service",
        fixture / "initial-cert.pem",
        fixture / "initial-key.pem",
        fixture / "renewed-cert.pem",
        fixture / "renewed-key.pem",
    )
    runner.run(
        CommandSpec(
            label="copy TLS reload fixture",
            argv=(
                "rsync",
                "-a",
                *(str(path) for path in sources),
                f"{manifest.protection.guest_copy_target}:{stage_path}/",
            ),
            cwd=root,
            timeout_seconds=120,
            scope=CommandScope.TEST,
        )
    )


def verify_remote_binaries(
    guest: GuestAgent,
    bundle: Bundle,
    stage_path: PurePosixPath,
) -> None:
    """Compare both staged guest binaries with the verified local bundle."""

    for name in ("vps-guard", "vps-guard-edge"):
        expected = hashlib.sha256((bundle.path / f"bin/{name}").read_bytes()).hexdigest()
        observed = guest_text(
            guest.execute(("/bin/sha256sum", f"{stage_path}/{name}")),
            f"{name} checksum",
        ).split()[0]
        if observed != expected:
            fail(
                "TLS_RELOAD_REMOTE_CHECKSUM_MISMATCH",
                "VM에 복사한 TLS probe binary checksum이 다릅니다.",
                name,
            )


def install_probe(guest: GuestAgent, stage_path: PurePosixPath) -> None:
    """Install an executable outside noexec /run and runtime state inside /run."""

    for directory, mode in (
        (RELOAD_RUNTIME, "0750"),
        (TEST_RUNTIME, "0750"),
        (TEST_INSTALL, "0750"),
        (f"{TEST_INSTALL}/initial", "0750"),
        (f"{TEST_INSTALL}/next", "0700"),
    ):
        guest.execute(
            (
                "/bin/install",
                "-d",
                "-o",
                "root",
                "-g",
                "vps-guard",
                "-m",
                mode,
                directory,
            )
        )
    installs = (
        ("0755", "root", "vps-guard", f"{stage_path}/vps-guard", f"{TEST_INSTALL}/vps-guard"),
        (
            "0755",
            "root",
            "vps-guard",
            f"{stage_path}/vps-guard-edge",
            f"{TEST_INSTALL}/vps-guard-edge",
        ),
        (
            "0640",
            "root",
            "vps-guard",
            f"{stage_path}/tls-reload-config.toml",
            f"{TEST_INSTALL}/config.toml",
        ),
        (
            "0440",
            "root",
            "vps-guard",
            f"{stage_path}/initial-cert.pem",
            f"{TEST_INSTALL}/initial/fullchain.pem",
        ),
        (
            "0440",
            "root",
            "vps-guard",
            f"{stage_path}/initial-key.pem",
            f"{TEST_INSTALL}/initial/privkey.pem",
        ),
        (
            "0400",
            "root",
            "root",
            f"{stage_path}/renewed-cert.pem",
            f"{TEST_INSTALL}/next/fullchain.pem",
        ),
        (
            "0400",
            "root",
            "root",
            f"{stage_path}/renewed-key.pem",
            f"{TEST_INSTALL}/next/privkey.pem",
        ),
        (
            "0644",
            "root",
            "root",
            f"{stage_path}/vps-guard-tls-probe.service",
            TEST_UNIT,
        ),
    )
    for mode, owner, group, source, target in installs:
        guest.execute(
            (
                "/bin/install",
                "-o",
                owner,
                "-g",
                group,
                "-m",
                mode,
                source,
                target,
            )
        )
    guest.execute(("/bin/systemctl", "daemon-reload"))


def verify_installed_probe(guest: GuestAgent) -> None:
    """Execute the installed Edge binary as the service account."""

    result = guest.execute(
        (
            "/sbin/runuser",
            "--user",
            "vps-guard",
            "--",
            f"{TEST_INSTALL}/vps-guard-edge",
            "--version",
        )
    )
    if not guest_text(result, "TLS reload binary version").startswith(
        "vps-guard-edge "
    ):
        fail(
            "TLS_RELOAD_BINARY_EXECUTION_FAILED",
            "설치한 TLS probe binary 실행 결과가 올바르지 않습니다.",
            result.stdout.strip(),
        )


def remove_probe(guest: GuestAgent) -> None:
    """Stop the isolated unit and remove every fixed test path."""

    guest.execute(
        ("/bin/systemctl", "stop", TEST_SERVICE),
        timeout_seconds=15,
        accepted_exit_codes=(0, 5),
    )
    guest.execute(("/bin/rm", "-f", "--", TEST_UNIT, UPGRADE_SOCKET))
    guest.execute(
        (
            "/bin/rm",
            "-rf",
            "--",
            TEST_INSTALL,
            TEST_RUNTIME,
            RELOAD_RUNTIME,
        )
    )
    guest.execute(("/bin/systemctl", "daemon-reload"))
    require_guest_paths_absent(guest)


def require_stage_absent(guest: GuestAgent, stage_path: PurePosixPath) -> None:
    """Refuse to reuse a previous commit-bound guest stage."""

    result = guest.execute(
        ("/bin/test", "!", "-e", str(stage_path)),
        accepted_exit_codes=(0, 1),
    )
    if result.exit_code != 0:
        fail("TLS_RELOAD_STAGE_EXISTS", "TLS reload stage가 이미 존재합니다.", str(stage_path))


def require_guest_paths_absent(guest: GuestAgent) -> None:
    """Require all isolated service, install, runtime and socket paths absent."""

    for path in (
        TEST_UNIT,
        TEST_INSTALL,
        TEST_RUNTIME,
        RELOAD_RUNTIME,
        UPGRADE_SOCKET,
    ):
        result = guest.execute(("/bin/test", "!", "-e", path), accepted_exit_codes=(0, 1))
        if result.exit_code != 0:
            fail("TLS_RELOAD_PATH_EXISTS", "TLS reload 전용 경로가 이미 존재합니다.", path)


def remove_stage(
    runner: CommandRunner,
    root: Path,
    manifest: TlsReloadManifest,
    stage_path: PurePosixPath,
) -> None:
    """Remove only the exact commit-bound guest-user stage."""

    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/rm", "-rf", "--", str(stage_path)),
        label="remove TLS reload stage",
    )


def wait_service_active(guest: GuestAgent, *, timeout_seconds: int = 20) -> None:
    """Wait through systemd activating and reject terminal states."""

    deadline = time.monotonic() + timeout_seconds
    state = "unknown"
    while time.monotonic() < deadline:
        result = guest.execute(
            ("/bin/systemctl", "is-active", TEST_SERVICE),
            accepted_exit_codes=(0, 3),
        )
        state = guest_text(result, "TLS reload service state")
        if state == "active":
            return
        if state in {"failed", "inactive", "deactivating"}:
            break
        time.sleep(0.2)
    fail("TLS_RELOAD_SERVICE_INACTIVE", "TLS reload probe service가 active가 아닙니다.", state)


def supervisor_pid(guest: GuestAgent) -> int:
    """Return a valid systemd MainPID for the isolated supervisor."""

    value = guest_text(
        guest.execute(
            (
                "/bin/systemctl",
                "show",
                TEST_SERVICE,
                "--property",
                "MainPID",
                "--value",
            )
        ),
        "TLS supervisor PID",
    )
    if not value.isdigit() or int(value) <= 1:
        fail("TLS_RELOAD_MAIN_PID_INVALID", "TLS supervisor MainPID가 올바르지 않습니다.", value)
    return int(value)


def wait_worker_count(
    guest: GuestAgent,
    supervisor_pid_value: int,
    *,
    expected: int,
    timeout_seconds: int,
) -> None:
    """Wait for an exact supervisor child count."""

    deadline = time.monotonic() + timeout_seconds
    observed = -1
    while time.monotonic() < deadline:
        result = guest.execute(
            ("/bin/pgrep", "-P", str(supervisor_pid_value)),
            accepted_exit_codes=(0, 1),
        )
        observed = len(
            [line for line in result.stdout.splitlines() if line.strip().isdigit()]
        )
        if observed == expected:
            return
        time.sleep(0.2)
    fail(
        "TLS_RELOAD_WORKER_COUNT_TIMEOUT",
        "Pingora worker 수가 예상 상태에 도달하지 않았습니다.",
        f"expected={expected}, observed={observed}",
    )


def restore_memory(
    runner: CommandRunner,
    guest: GuestAgent,
    root: Path,
    manifest: TlsReloadManifest,
    original_memory: int,
    balloon_was_loaded: bool,
) -> tuple[bool, bool]:
    """Restore exact libvirt memory and original balloon module state."""

    try:
        set_domain_memory(runner, root, manifest.protection, original_memory)
        memory_restored = wait_domain_memory(
            runner,
            root,
            manifest.protection,
            original_memory,
        )
        balloon_restored = restore_balloon_driver(
            guest,
            was_loaded=balloon_was_loaded,
        )
    except Exception:
        return False, False
    return memory_restored, balloon_restored
