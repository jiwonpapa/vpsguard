"""Isolated OPS-005/OPS-006 update rollback and uninstall execution harness."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .runner import CommandResult, CommandRunner, CommandScope, CommandSpec


class ReleaseLifecycleError(HarnessError):
    """The isolated release lifecycle violated an ownership invariant."""


@dataclass(frozen=True)
class ReleaseLifecycleSummary:
    """Successful lifecycle command results."""

    results: tuple[CommandResult, ...]
    scenarios: int


_RELEASE_ID = "0123456789abcdef0123456789abcdef01234567"
_BINARIES = ("vps-guard", "vps-guard-control", "vps-guard-privileged", "vps-guard-edge")
_UNITS = (
    "vps-guard-control.service",
    "vps-guard-privileged.service",
    "vps-guard-privileged.socket",
    "vps-guard-edge.service",
)


def run_release_lifecycle_harness(repository: Path) -> ReleaseLifecycleSummary:
    """Execute success, health-fault rollback and owned-only uninstall fixtures."""

    cli = repository / "target/debug/vps-guard"
    runner = CommandRunner()
    results = [
        runner.run(
            CommandSpec(
                label="build release lifecycle operation binary",
                argv=("cargo", "build", "--quiet", "-p", "guard-cli"),
                cwd=repository,
                timeout_seconds=300,
                scope=CommandScope.BUILD,
            )
        )
    ]
    if not cli.is_file():
        _raise_lifecycle("operation binary is unavailable", [f"path={cli}"])

    with tempfile.TemporaryDirectory(prefix="vpsguard-release-lifecycle-") as directory:
        workspace = Path(directory)
        wrappers = workspace / "bin"
        _write_wrappers(wrappers)
        bundle = workspace / "bundle"
        _write_bundle(repository, bundle)

        success_root = workspace / "success-root"
        _write_installed_fixture(repository, success_root)
        results.append(
            _run_update(
                runner,
                repository,
                cli,
                wrappers,
                bundle,
                success_root,
                fail_edge_health=False,
            )
        )
        _assert_update_success(success_root)
        results.append(_run_uninstall(runner, repository, wrappers, success_root))
        _assert_uninstall(success_root)

        rollback_root = workspace / "rollback-root"
        _write_installed_fixture(repository, rollback_root)
        results.append(
            _run_update(
                runner,
                repository,
                cli,
                wrappers,
                bundle,
                rollback_root,
                fail_edge_health=True,
            )
        )
        _assert_rollback(rollback_root)

    return ReleaseLifecycleSummary(results=tuple(results), scenarios=3)


def _run_update(
    runner: CommandRunner,
    repository: Path,
    cli: Path,
    wrappers: Path,
    bundle: Path,
    root: Path,
    *,
    fail_edge_health: bool,
) -> CommandResult:
    snapshots = root.parent / f"{root.name}-snapshots"
    lock_root = root.parent / f"{root.name}-lock"
    environment = _fixture_environment(wrappers, root) + (
        f"VPS_GUARD_SNAPSHOT_ROOT={snapshots}",
        f"VPS_GUARD_OPERATION_LOCK_ROOT={lock_root}",
        f"VPS_GUARD_OPERATION_BINARY={cli}",
        "VPS_GUARD_UPDATE_CONFIRM=update-with-rollback",
        "VPS_GUARD_EDGE_HOST=fixture.example",
        "VPS_GUARD_CONTROL_HEALTH_URL=http://fixture/control",
        "VPS_GUARD_EDGE_HEALTH_URL=http://fixture/edge",
        f"VPS_GUARD_FIXTURE_FAIL_URL={'http://fixture/edge' if fail_edge_health else ''}",
    )
    return runner.run(
        CommandSpec(
            label="release update rollback fault" if fail_edge_health else "release update success",
            argv=(
                "env",
                *environment,
                "bash",
                str(repository / "scripts/update-release.sh"),
                "--apply",
                str(bundle),
            ),
            cwd=repository,
            timeout_seconds=60,
            scope=CommandScope.TEST,
            accepted_exit_codes=(22,) if fail_edge_health else (0,),
        )
    )


def _run_uninstall(
    runner: CommandRunner,
    repository: Path,
    wrappers: Path,
    root: Path,
) -> CommandResult:
    environment = _fixture_environment(wrappers, root) + (
        "VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only",
        "VPS_GUARD_BYPASS_VERIFIED=nginx-public",
        "VPS_GUARD_UNINSTALL_PROBE_URL=http://fixture/public",
    )
    return runner.run(
        CommandSpec(
            label="owned-only uninstall",
            argv=(
                "env",
                *environment,
                "bash",
                str(repository / "scripts/uninstall.sh"),
                "--apply",
            ),
            cwd=repository,
            timeout_seconds=30,
            scope=CommandScope.TEST,
        )
    )


def _fixture_environment(wrappers: Path, root: Path) -> tuple[str, ...]:
    return (
        f"PATH={wrappers}{os.pathsep}{os.environ.get('PATH', '')}",
        f"VPS_GUARD_TEST_ROOT={root}",
        "VPS_GUARD_FIXTURE_CONFIRM=isolated-root",
    )


def _write_installed_fixture(repository: Path, root: Path) -> None:
    for parts in (("usr", "lib", "tmpfiles.d"), ("etc", "pam.d")):
        (root / _relative(*parts)).mkdir(parents=True)
    old_release = root / _relative("usr", "local", "lib", "vps-guard", "releases", "old", "bin")
    old_release.mkdir(parents=True)
    for binary in _BINARIES:
        _write(old_release / binary, f"old-{binary}\n", executable=True)
    current = root / _relative("usr", "local", "lib", "vps-guard", "current")
    current.symlink_to(_logical("usr", "local", "lib", "vps-guard", "releases", "old"))
    binary_root = root / _relative("usr", "local", "bin")
    binary_root.mkdir(parents=True)
    for binary in _BINARIES:
        (binary_root / binary).symlink_to(
            _logical("usr", "local", "lib", "vps-guard", "current", "bin", binary)
        )

    _write(root / _relative("etc", "vps-guard", "config.toml"), "fixture-config\n")
    _write(
        root / _relative("var", "lib", "vps-guard", "state.json"),
        "fixture-runtime-state\n",
    )
    for unit in _UNITS:
        _write(root / _relative("etc", "systemd", "system", unit), f"old-{unit}\n")
        _service_state(root, unit, "enabled", "active")
    _service_state(root, "nginx.service", "enabled", "active")
    for path, content in (
        ((_relative("etc", "ssh", "sshd_config")), "ssh-sentinel\n"),
        ((_relative("etc", "nginx", "sites-enabled", "site.conf")), "nginx-sentinel\n"),
        (
            (_relative("etc", "letsencrypt", "live", "fixture", "fullchain.pem")),
            "certificate-sentinel\n",
        ),
        ((_relative("home", "g7devops", "public_html", "index.php")), "site-sentinel\n"),
    ):
        _write(root / path, content)
    _write(
        root / _relative("var", "lib", "vps-guard", "ownership-manifest.txt"),
        (repository / "packaging/ownership-manifest.txt").read_text(encoding="utf-8"),
    )
    _write(root / _relative(".vpsguard-test", "listeners"), "127.0.0.1:22\n")


def _write_bundle(repository: Path, bundle: Path) -> None:
    for binary in _BINARIES:
        _write(
            bundle / "bin" / binary,
            "#!/usr/bin/env sh\nexit 0\n",
            executable=True,
        )
    for unit in _UNITS:
        _copy(
            repository / "packaging/systemd" / unit,
            bundle / "systemd" / unit,
        )
    _copy(
        repository / "packaging/systemd/vps-guard-control-cloudflare-credential.conf",
        bundle / "systemd/vps-guard-control.service.d/20-cloudflare-credential.conf",
    )
    _copy(
        repository / "packaging/tmpfiles/vps-guard.conf",
        bundle / "tmpfiles/vps-guard.conf",
    )
    _copy(repository / "packaging/pam/vps-guard", bundle / "pam/vps-guard")
    for name in ("deployment-state.sh", "state-common.sh", "operation-lock.sh"):
        _copy(repository / "scripts" / name, bundle / "scripts" / name)
    _copy(
        repository / "packaging/ownership-manifest.txt",
        bundle / "ownership-manifest.txt",
    )
    _write(bundle / "BUILD-INFO.txt", f"fixture\n{_RELEASE_ID}\n")
    checksums = []
    for path in sorted(bundle.rglob("*")):
        if path.is_file():
            checksums.append(f"{_sha256(path)}  {path.relative_to(bundle)}")
    _write(bundle / "SHA256SUMS", "\n".join(checksums) + "\n")


def _write_wrappers(directory: Path) -> None:
    python = sys.executable
    wrappers = {
        "curl": f"""#!{python}
import os, sys
url = sys.argv[-1]
raise SystemExit(22 if os.environ.get("VPS_GUARD_FIXTURE_FAIL_URL") == url else 0)
""",
        "mv": f"""#!{python}
import os, sys
arguments = [value for value in sys.argv[1:] if value != "-Tf"]
os.replace(arguments[-2], arguments[-1])
""",
        "nginx": f"#!{python}\nraise SystemExit(0)\n",
        "ss": f"#!{python}\nraise SystemExit(0)\n",
        "systemd-tmpfiles": f"#!{python}\nraise SystemExit(0)\n",
        "sha256sum": f"""#!{python}
import hashlib, pathlib, sys
if sys.argv[1] == "--check":
    for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = pathlib.Path(name.strip())
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(1)
    raise SystemExit(0)
for name in sys.argv[1:]:
    path = pathlib.Path(name)
    print(hashlib.sha256(path.read_bytes()).hexdigest(), name)
""",
        "systemctl": f"""#!{python}
import os, pathlib, sys
root = pathlib.Path(os.environ["VPS_GUARD_TEST_ROOT"])
state = root / ".vpsguard-test" / "systemd"
arguments = sys.argv[1:]
action = arguments[0]
units = [value for value in arguments[1:] if value.endswith((".service", ".socket"))]
if action == "is-active":
    marker = state / (units[0] + ".active")
    raise SystemExit(0 if marker.read_text().strip() == "active" else 3)
if action in ("start", "stop"):
    for unit in units:
        state.mkdir(parents=True, exist_ok=True)
        (state / (unit + ".active")).write_text("active\\n" if action == "start" else "inactive\\n")
if action == "disable":
    for unit in units:
        state.mkdir(parents=True, exist_ok=True)
        (state / (unit + ".enabled")).write_text("disabled\\n")
        if "--now" in arguments:
            (state / (unit + ".active")).write_text("inactive\\n")
raise SystemExit(0)
""",
    }
    for name, content in wrappers.items():
        _write(directory / name, content, executable=True)


def _assert_update_success(root: Path) -> None:
    current = root / _relative("usr", "local", "lib", "vps-guard", "current")
    expected = Path(_logical("usr", "local", "lib", "vps-guard", "releases", _RELEASE_ID))
    failures = []
    if not current.is_symlink() or current.readlink() != expected:
        failures.append(f"current release mismatch: {current}")
    if not (root / _relative("usr", "local", "lib", "vps-guard", "releases", _RELEASE_ID)).is_dir():
        failures.append("versioned release is missing")
    if _read(root, "etc", "systemd", "system", "vps-guard-control.service").startswith("old-"):
        failures.append("systemd unit was not updated")
    failures.extend(_protected_failures(root))
    if failures:
        _raise_lifecycle("successful update did not reach the candidate state", failures)


def _assert_rollback(root: Path) -> None:
    current = root / _relative("usr", "local", "lib", "vps-guard", "current")
    expected = Path(_logical("usr", "local", "lib", "vps-guard", "releases", "old"))
    failures = []
    if not current.is_symlink() or current.readlink() != expected:
        failures.append("current release was not restored")
    candidate = root / _relative("usr", "local", "lib", "vps-guard", "releases", _RELEASE_ID)
    if candidate.exists():
        failures.append("failed candidate release remains")
    if _read(root, "etc", "systemd", "system", "vps-guard-control.service") != (
        "old-vps-guard-control.service\n"
    ):
        failures.append("systemd unit was not restored")
    if _service_value(root, "vps-guard-edge.service", "active") != "active":
        failures.append("edge service activity was not restored")
    failures.extend(_protected_failures(root))
    if failures:
        _raise_lifecycle("health failure did not restore the exact pre-update state", failures)


def _assert_uninstall(root: Path) -> None:
    failures = []
    for binary in _BINARIES:
        if (root / _relative("usr", "local", "bin", binary)).exists():
            failures.append(f"owned binary remains: {binary}")
    if (root / _relative("usr", "local", "lib", "vps-guard", "releases")).exists():
        failures.append("owned releases remain")
    if (root / _relative("etc", "systemd", "system", "vps-guard-edge.service")).exists():
        failures.append("owned systemd unit remains")
    if _read(root, "etc", "vps-guard", "config.toml") != "fixture-config\n":
        failures.append("configuration was not preserved")
    if _read(root, "var", "lib", "vps-guard", "state.json") != "fixture-runtime-state\n":
        failures.append("runtime state was not preserved")
    failures.extend(_protected_failures(root))
    if failures:
        _raise_lifecycle("uninstall crossed the owned-artifact boundary", failures)


def _protected_failures(root: Path) -> list[str]:
    expected = (
        (("etc", "ssh", "sshd_config"), "ssh-sentinel\n"),
        (("etc", "nginx", "sites-enabled", "site.conf"), "nginx-sentinel\n"),
        (
            ("etc", "letsencrypt", "live", "fixture", "fullchain.pem"),
            "certificate-sentinel\n",
        ),
        (("home", "g7devops", "public_html", "index.php"), "site-sentinel\n"),
    )
    return [
        f"protected path changed: {'/'.join(parts)}"
        for parts, content in expected
        if _read(root, *parts) != content
    ]


def _service_state(root: Path, unit: str, enabled: str, active: str) -> None:
    base = root / _relative(".vpsguard-test", "systemd")
    _write(base / f"{unit}.enabled", f"{enabled}\n")
    _write(base / f"{unit}.active", f"{active}\n")


def _service_value(root: Path, unit: str, state: str) -> str:
    return _read(root, ".vpsguard-test", "systemd", f"{unit}.{state}").strip()


def _read(root: Path, *parts: str) -> str:
    return (root / _relative(*parts)).read_text(encoding="utf-8")


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _logical(*parts: str) -> str:
    return "/" + "/".join(parts)


def _relative(*parts: str) -> Path:
    return Path(*parts)


def _raise_lifecycle(problem: str, details: list[str]) -> None:
    raise ReleaseLifecycleError(
        code="RELEASE_LIFECYCLE_CONTRACT_FAILED",
        problem=problem,
        cause="; ".join(details),
        impact="업데이트 자동 원복 또는 소유 파일 전용 제거를 자동 검증 완료로 표시하지 않았습니다.",
        next_action="실패 fixture의 transaction state와 파일 경계를 확인한 뒤 다시 실행하십시오.",
    )
