"""Bounded root guest operations for OPS-006 uninstall and exact lab restore."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath

from .protection_pilot_model import Bundle
from .protection_pilot_remote import guest_text
from .qga import GuestAgent
from .uninstall_pilot_model import UninstallPilotManifest, fail

APACHE_STAGE_BASE = "/tmp/vpsguard-apache."
_PROTECTED_FILES = {
    "ssh_config": PurePosixPath("/", "etc", "ssh", "sshd_config"),
    "site_index": PurePosixPath("/", "home", "gnuboard5", "public_html", "index.php"),
    "certificate": PurePosixPath("/", "etc", "ssl", "gnuboard5", "gnuboard5.local.pem"),
    "apache_public_vhost": PurePosixPath(
        "/", "etc", "apache2", "sites-available", "gnuboard5.conf"
    ),
    "apache_origin_vhost": PurePosixPath(
        "/", "etc", "apache2", "sites-available", "vpsguard-origin.conf"
    ),
    "apache_origin_ports": PurePosixPath(
        "/", "etc", "apache2", "conf-available", "vpsguard-origin-ports.conf"
    ),
    "guard_config": PurePosixPath("/", "etc", "vps-guard", "config.toml"),
    "ownership_manifest": PurePosixPath(
        "/", "var", "lib", "vps-guard", "ownership-manifest.txt"
    ),
}
_METADATA_ONLY = {
    "certificate_key_metadata": PurePosixPath(
        "/", "etc", "ssl", "gnuboard5", "gnuboard5.local-key.pem"
    ),
    "runtime_state_metadata": PurePosixPath(
        "/", "var", "lib", "vps-guard", "state.json"
    ),
}
_REMOVED_PATHS = (
    PurePosixPath("/", "usr", "local", "bin", "vps-guard"),
    PurePosixPath("/", "usr", "local", "bin", "vps-guard-control"),
    PurePosixPath("/", "usr", "local", "bin", "vps-guard-privileged"),
    PurePosixPath("/", "usr", "local", "bin", "vps-guard-edge"),
    PurePosixPath("/", "usr", "local", "lib", "vps-guard", "current"),
    PurePosixPath("/", "usr", "local", "lib", "vps-guard", "releases"),
    PurePosixPath("/", "usr", "local", "libexec", "vps-guard", "deployment-state"),
    PurePosixPath("/", "usr", "local", "libexec", "vps-guard", "state-common.sh"),
    PurePosixPath("/", "etc", "systemd", "system", "vps-guard-control.service"),
    PurePosixPath("/", "etc", "systemd", "system", "vps-guard-privileged.service"),
    PurePosixPath("/", "etc", "systemd", "system", "vps-guard-privileged.socket"),
    PurePosixPath("/", "etc", "systemd", "system", "vps-guard-edge.service"),
    PurePosixPath("/", "usr", "lib", "tmpfiles.d", "vps-guard.conf"),
    PurePosixPath("/", "etc", "pam.d", "vps-guard"),
)
_VPSGUARD_WEB_PORTS = {80, 443, 7443, 7727, 18080, 18081}


def required_bundle_paths(bundle: Bundle) -> tuple[Path, ...]:
    """Return every release artifact required by the uninstall pilot."""

    return tuple(
        bundle.path / relative
        for relative in (
            "bin/vps-guard",
            "scripts/deployment-state.sh",
            "scripts/state-common.sh",
            "scripts/uninstall.sh",
            "ownership-manifest.txt",
            "gnuboard5/apache/gnuboard5-guarded.conf",
            "gnuboard5/apache/gnuboard5-bypass.conf",
            "gnuboard5/apache/vpsguard-origin.conf",
            "gnuboard5/apache/vpsguard-origin-ports.conf",
            "gnuboard5/vps-guard.enforce.toml",
        )
    )


def require_bundle_layout(bundle: Bundle) -> None:
    """Reject a verified checksum set that omits an uninstall dependency."""

    missing = [str(path.relative_to(bundle.path)) for path in required_bundle_paths(bundle) if not path.is_file()]
    if missing:
        fail(
            "UNINSTALL_BUNDLE_INCOMPLETE",
            "uninstall pilot bundle 파일이 부족합니다.",
            ",".join(missing),
        )


def verify_staged_bundle(
    guest: GuestAgent,
    bundle: Bundle,
    bundle_stage: PurePosixPath,
) -> None:
    """Compare every required staged file with its verified local artifact."""

    for local in required_bundle_paths(bundle):
        relative = local.relative_to(bundle.path)
        expected = hashlib.sha256(local.read_bytes()).hexdigest()
        observed = guest_text(
            guest.execute(("/bin/sha256sum", f"{bundle_stage}/bundle/{relative}")),
            f"staged bundle {relative}",
        ).split()[0]
        if observed != expected:
            fail(
                "UNINSTALL_REMOTE_CHECKSUM_MISMATCH",
                "VM에 복사한 uninstall bundle 파일이 다릅니다.",
                str(relative),
            )


def apache_stage_path(bundle: Bundle) -> PurePosixPath:
    """Return one fixed-format Apache stage owned by this source commit."""

    return PurePosixPath(f"{APACHE_STAGE_BASE}ops006{bundle.source_commit[:12]}")


def require_guest_paths_absent(
    guest: GuestAgent,
    apache_stage: PurePosixPath,
) -> None:
    """Refuse to reuse a stale Apache mutation path."""

    result = guest.execute(
        ("/bin/test", "!", "-e", str(apache_stage)),
        accepted_exit_codes=(0, 1),
    )
    if result.exit_code != 0:
        fail(
            "UNINSTALL_STAGE_EXISTS",
            "uninstall 전용 경로가 이미 존재합니다.",
            str(apache_stage),
        )


def prepare_apache_stage(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
    apache_stage: PurePosixPath,
) -> None:
    """Install five validated Apache candidate files into a private root stage."""

    guest.execute(("/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", str(apache_stage)))
    sources = (
        ("gnuboard5/apache/gnuboard5-guarded.conf", "gnuboard5-guarded.conf"),
        ("gnuboard5/apache/gnuboard5-bypass.conf", "gnuboard5-bypass.conf"),
        ("gnuboard5/apache/vpsguard-origin.conf", "vpsguard-origin.conf"),
        ("gnuboard5/apache/vpsguard-origin-ports.conf", "vpsguard-origin-ports.conf"),
        ("gnuboard5/vps-guard.enforce.toml", "vps-guard.ingress.toml"),
    )
    for source, destination in sources:
        guest.execute(
            (
                "/bin/install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0600",
                f"{bundle_stage}/bundle/{source}",
                f"{apache_stage}/{destination}",
            )
        )


def create_release_snapshot(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
) -> tuple[str, int, int]:
    """Create the Rust-validated bounded versioned release snapshot."""

    result = guest.execute(
        (
            f"{bundle_stage}/bundle/bin/vps-guard",
            "ops",
            "uninstall-release",
            "snapshot",
        ),
        environment=("VPS_GUARD_UNINSTALL_RELEASE_CONFIRM=snapshot-release-tree",),
        timeout_seconds=60,
    )
    path = _required_output(result.stdout, "uninstall_snapshot")
    release_count = _required_count(result.stdout, "release_count", maximum=8)
    binary_count = _required_count(result.stdout, "binary_count", maximum=32)
    if binary_count != release_count * 4:
        fail(
            "UNINSTALL_RELEASE_SNAPSHOT_INVALID",
            "release snapshot binary 수가 일치하지 않습니다.",
            f"releases={release_count}, binaries={binary_count}",
        )
    return path, release_count, binary_count


def restore_release_snapshot(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
    snapshot: str,
) -> None:
    """Restore the Rust-validated release snapshot after owned-only uninstall."""

    guest.execute(
        (
            f"{bundle_stage}/bundle/bin/vps-guard",
            "ops",
            "uninstall-release",
            "restore",
            snapshot,
        ),
        environment=("VPS_GUARD_UNINSTALL_RELEASE_CONFIRM=restore-release-tree",),
        timeout_seconds=60,
    )
    verify_release_snapshot(guest, bundle_stage, snapshot)


def verify_release_snapshot(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
    snapshot: str,
) -> None:
    """Verify the immutable release snapshot checksum and payload contract."""

    guest.execute(
        (
            f"{bundle_stage}/bundle/bin/vps-guard",
            "ops",
            "uninstall-release",
            "verify",
            snapshot,
        ),
        timeout_seconds=60,
    )


def remove_release_snapshot(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
    snapshot: str,
) -> None:
    """Remove only the exact Rust-validated uninstall release snapshot."""

    guest.execute(
        (
            f"{bundle_stage}/bundle/bin/vps-guard",
            "ops",
            "uninstall-release",
            "remove",
            snapshot,
        ),
        environment=("VPS_GUARD_UNINSTALL_RELEASE_CONFIRM=remove-release-snapshot",),
        timeout_seconds=60,
    )


def capture_protected_fingerprints(guest: GuestAgent) -> dict[str, str]:
    """Hash bounded public/config sentinels and metadata, never site trees or key bytes."""

    fingerprints = {}
    for label, path in _PROTECTED_FILES.items():
        digest = guest_text(
            guest.execute(("/bin/sha256sum", str(path))),
            f"protected {label}",
        ).split()[0]
        fingerprints[label] = digest
    for label, path in _METADATA_ONLY.items():
        metadata = guest_text(
            guest.execute(("/bin/stat", "--format=%F|%a|%u|%g", str(path))),
            f"protected metadata {label}",
        )
        fingerprints[label] = hashlib.sha256(metadata.encode()).hexdigest()
    ufw = guest.execute(("/sbin/ufw", "status", "numbered")).stdout
    fingerprints["ufw_rules"] = hashlib.sha256(ufw.encode()).hexdigest()
    return fingerprints


def protected_listener_ports(guest: GuestAgent) -> tuple[int, ...]:
    """Return non-web TCP listener ports without process, PID or address disclosure."""

    output = guest.execute(("/bin/ss", "-H", "-ltn")).stdout
    ports = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        value = fields[3].rsplit(":", maxsplit=1)[-1]
        if value.isdigit() and int(value) not in _VPSGUARD_WEB_PORTS:
            ports.add(int(value))
    if 22 not in ports:
        fail("UNINSTALL_SSH_LISTENER_MISSING", "SSH listener를 찾지 못했습니다.", repr(sorted(ports)))
    return tuple(sorted(ports))


def create_deployment_snapshot(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
) -> str:
    """Create one typed VPSGuard-owned deployment snapshot."""

    result = guest.execute(
        (
            "/bin/bash",
            f"{bundle_stage}/bundle/scripts/deployment-state.sh",
            "--snapshot",
        ),
        environment=(
            "LANG=C",
            f"VPS_GUARD_OPERATION_BINARY={bundle_stage}/bundle/bin/vps-guard",
        ),
        timeout_seconds=30,
    )
    match = re.search(r"^snapshot=(/\S+)$", result.stdout, flags=re.MULTILINE)
    if match is None:
        fail("UNINSTALL_SNAPSHOT_MISSING", "deployment snapshot을 찾지 못했습니다.", result.stdout)
    return match.group(1)


def apply_apache_direction(
    guest: GuestAgent,
    bundle_stage: PurePosixPath,
    apache_stage: PurePosixPath,
    direction: str,
) -> tuple[int, tuple[str, ...]]:
    """Apply one typed Apache direction and return duration plus generated paths."""

    import time

    if direction not in {"to-apache", "to-edge"}:
        fail("UNINSTALL_APACHE_DIRECTION_INVALID", "Apache 방향이 올바르지 않습니다.", direction)
    started = time.monotonic_ns()
    result = guest.execute(
        (
            f"{bundle_stage}/bundle/bin/vps-guard",
            "ops",
            "apache-ingress",
            "apply",
            "--direction",
            direction,
            "--stage",
            str(apache_stage),
        ),
        environment=(
            "LANG=C",
            f"VPS_GUARD_APACHE_INGRESS_CONFIRM={direction}",
            "VPS_GUARD_APACHE_PROBE_URL=https://gnuboard5.local/",
        ),
        timeout_seconds=30,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    return elapsed, generated_paths(result.stdout)


def uninstall_environment(manifest: UninstallPilotManifest) -> tuple[str, ...]:
    """Return the exact explicit production uninstall confirmations."""

    return (
        "LANG=C",
        "VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only",
        f"VPS_GUARD_BYPASS_VERIFIED={manifest.ingress}",
        f"VPS_GUARD_UNINSTALL_PROBE_URL={manifest.endurance.probe_url}",
    )


def run_uninstall(
    guest: GuestAgent,
    manifest: UninstallPilotManifest,
    bundle_stage: PurePosixPath,
) -> int:
    """Run the packaged uninstall script and enforce its hard duration budget."""

    import time

    started = time.monotonic_ns()
    guest.execute(
        (
            "/bin/bash",
            f"{bundle_stage}/bundle/scripts/uninstall.sh",
            "--apply",
        ),
        environment=uninstall_environment(manifest),
        timeout_seconds=30,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    if elapsed > manifest.max_uninstall_ms:
        fail(
            "UNINSTALL_BUDGET_EXCEEDED",
            "uninstall 시간 예산을 초과했습니다.",
            f"elapsed_ms={elapsed}",
        )
    return elapsed


def require_post_uninstall(guest: GuestAgent) -> dict[str, object]:
    """Require Apache direct service while every owned executable/unit is absent."""

    apache = guest_text(
        guest.execute(("/bin/systemctl", "is-active", "apache2.service")),
        "Apache post uninstall",
    )
    edge = guest_text(
        guest.execute(
            ("/bin/systemctl", "is-active", "vps-guard-edge.service"),
            accepted_exit_codes=(0, 3, 4),
        ),
        "Edge post uninstall",
    )
    enabled = guest_text(
        guest.execute(
            ("/bin/systemctl", "is-enabled", "vps-guard-edge.service"),
            accepted_exit_codes=(0, 1),
        ),
        "Edge enablement post uninstall",
    )
    remaining: list[str] = []
    for path in _REMOVED_PATHS:
        result = guest.execute(
            ("/bin/test", "!", "-e", str(path)),
            accepted_exit_codes=(0, 1),
        )
        if result.exit_code != 0:
            remaining.append(str(path))
    if apache != "active" or edge not in {"inactive", "unknown"} or enabled not in {
        "disabled",
        "not-found",
    } or remaining:
        fail(
            "UNINSTALL_READBACK_FAILED",
            "uninstall 소유 경계 read-back이 일치하지 않습니다.",
            f"apache={apache}, edge={edge}, enabled={enabled}, remaining={remaining}",
        )
    return {
        "apache_active": True,
        "edge_inactive": True,
        "edge_disabled_or_absent": True,
        "owned_paths_absent": True,
    }


def restore_deployment(
    guest: GuestAgent,
    manifest: UninstallPilotManifest,
    bundle_stage: PurePosixPath,
    snapshot: str,
) -> tuple[int, tuple[str, ...]]:
    """Restore the typed deployment snapshot using the staged verified CLI."""

    import time

    started = time.monotonic_ns()
    result = guest.execute(
        (
            "/bin/bash",
            f"{bundle_stage}/bundle/scripts/deployment-state.sh",
            "--restore",
            snapshot,
        ),
        environment=(
            "LANG=C",
            "VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot",
            f"VPS_GUARD_OPERATION_BINARY={bundle_stage}/bundle/bin/vps-guard",
        ),
        timeout_seconds=30,
    )
    elapsed = (time.monotonic_ns() - started) // 1_000_000
    if elapsed > manifest.max_restore_ms:
        fail(
            "UNINSTALL_RESTORE_BUDGET_EXCEEDED",
            "deployment restore 시간 예산을 초과했습니다.",
            f"elapsed_ms={elapsed}",
        )
    return elapsed, generated_paths(result.stdout)


def generated_paths(output: str) -> tuple[str, ...]:
    """Extract only typed snapshot and transaction paths from CLI output."""

    paths = []
    for key in ("snapshot", "rollback_snapshot", "transaction_state"):
        match = re.search(rf"^{key}=(/\S+)$", output, flags=re.MULTILINE)
        if match is None or match.group(1) == "none":
            continue
        path = PurePosixPath(match.group(1))
        paths.append(str(path.parent if key == "transaction_state" else path))
    return tuple(paths)


def remove_apache_stage(guest: GuestAgent, apache_stage: PurePosixPath) -> None:
    """Remove only the fixed Apache stage after exact restore."""

    guest.execute(("/bin/rm", "-rf", "--", str(apache_stage)))
    result = guest.execute(
        ("/bin/test", "!", "-e", str(apache_stage)),
        accepted_exit_codes=(0, 1),
    )
    if result.exit_code != 0:
        fail(
            "UNINSTALL_CLEANUP_FAILED",
            "uninstall Apache stage가 남았습니다.",
            str(apache_stage),
        )


def _required_output(output: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}=(/\S+)$", output, flags=re.MULTILINE)
    if match is None:
        fail(
            "UNINSTALL_RELEASE_OUTPUT_INVALID",
            "release snapshot CLI 출력이 올바르지 않습니다.",
            f"missing={key}",
        )
    return match.group(1)


def _required_count(output: str, key: str, *, maximum: int) -> int:
    match = re.search(rf"^{re.escape(key)}=(\d+)$", output, flags=re.MULTILINE)
    value = int(match.group(1)) if match is not None else 0
    if not 1 <= value <= maximum:
        fail(
            "UNINSTALL_RELEASE_OUTPUT_INVALID",
            "release snapshot count가 올바르지 않습니다.",
            f"{key}={value}",
        )
    return value
