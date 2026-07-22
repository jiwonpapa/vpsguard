"""Explicit developer-scoped verification plans for fast local feedback."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .runner import CommandResult, CommandRunner, CommandScope, CommandSpec


class DevCheckError(HarnessError):
    """A requested developer check scope is invalid or cannot run."""


@dataclass(frozen=True)
class DevCheckPlan:
    """Bounded commands for one explicitly selected development surface."""

    scope: str
    commands: tuple[CommandSpec, ...]


@dataclass(frozen=True)
class DevCheckSummary:
    """Successful command results for one developer-scoped check."""

    scope: str
    results: tuple[CommandResult, ...]

    def display(self) -> str:
        """Return a compact stable summary for terminal and CI logs."""

        elapsed_ms = sum(result.elapsed_ms for result in self.results)
        return (
            f"developer check: PASS (scope={self.scope}, "
            f"commands={len(self.results)}, elapsed_ms={elapsed_ms})"
        )


def build_dev_check_plan(root: Path, scope: str) -> DevCheckPlan:
    """Build a non-mutating check plan without workspace-wide Rust compilation."""

    repository = root.resolve()
    if scope == "python":
        return DevCheckPlan(
            scope=scope,
            commands=(
                _command(
                    "Python harness unit tests",
                    (
                        "python3",
                        "-W",
                        "error::ResourceWarning",
                        "-m",
                        "unittest",
                        "discover",
                        "-s",
                        "tools/tests",
                        "-p",
                        "test_*.py",
                    ),
                    repository,
                    180,
                ),
                _command(
                    "harness language boundary",
                    ("python3", "-m", "tools.vpsguard_harness", "language-policy"),
                    repository,
                    30,
                ),
            ),
        )
    if scope == "web":
        web = repository / "web"
        if not web.is_dir():
            _raise_invalid_scope(scope, "web directory is missing")
        return DevCheckPlan(
            scope=scope,
            commands=(_command("Web check", ("bun", "run", "check"), web, 300),),
        )

    crates = _workspace_crates(repository)
    if scope not in crates:
        _raise_invalid_scope(scope, f"allowed={','.join(sorted(crates | {'python', 'web'}))}")
    return DevCheckPlan(
        scope=scope,
        commands=(
            _command("Rust format", ("cargo", "fmt", "--all", "--", "--check"), repository, 60),
            _command(
                f"Rust clippy {scope}",
                (
                    "cargo",
                    "clippy",
                    "--locked",
                    "-p",
                    scope,
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ),
                repository,
                900,
            ),
            _command(
                f"Rust test {scope}",
                ("cargo", "test", "--locked", "-p", scope, "--all-features"),
                repository,
                900,
            ),
        ),
    )


def run_dev_check(root: Path, scope: str) -> DevCheckSummary:
    """Execute the selected plan and stop at the first failed command."""

    plan = build_dev_check_plan(root, scope)
    runner = CommandRunner()
    return DevCheckSummary(
        scope=scope,
        results=tuple(runner.run(command) for command in plan.commands),
    )


def _workspace_crates(root: Path) -> set[str]:
    manifest = root / "Cargo.toml"
    try:
        with manifest.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DevCheckError(
            code="DEV_CHECK_WORKSPACE_INVALID",
            problem="Cargo workspace를 읽지 못했습니다.",
            cause=f"path={manifest}, error={error}",
            impact="Rust 범위 검증을 실행하지 않았습니다.",
            next_action="workspace Cargo.toml의 존재와 문법을 확인하십시오.",
        ) from error
    members = parsed.get("workspace", {}).get("members", [])
    if not isinstance(members, list) or any(not isinstance(member, str) for member in members):
        _raise_invalid_scope("rust", "workspace.members must be a string list")
    crates: set[str] = set()
    repository = root.resolve()
    for member in members:
        member_path = (repository / member).resolve(strict=False)
        if not member.startswith("crates/") or not member_path.is_relative_to(repository):
            continue
        package = _read_package_name(member_path / "Cargo.toml")
        crates.add(package)
    return crates


def _read_package_name(manifest: Path) -> str:
    try:
        with manifest.open("rb") as handle:
            parsed = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DevCheckError(
            code="DEV_CHECK_PACKAGE_INVALID",
            problem="Cargo package를 읽지 못했습니다.",
            cause=f"path={manifest}, error={error}",
            impact="Rust 범위 검증을 실행하지 않았습니다.",
            next_action="workspace member의 Cargo.toml과 package.name을 확인하십시오.",
        ) from error
    name = parsed.get("package", {}).get("name")
    if not isinstance(name, str) or not name:
        raise DevCheckError(
            code="DEV_CHECK_PACKAGE_INVALID",
            problem="Cargo package 이름이 올바르지 않습니다.",
            cause=f"path={manifest}, package.name={name!r}",
            impact="Rust 범위 검증을 실행하지 않았습니다.",
            next_action="workspace member의 package.name을 설정하십시오.",
        )
    return name


def _command(
    label: str,
    argv: tuple[str, ...],
    cwd: Path,
    timeout_seconds: float,
) -> CommandSpec:
    return CommandSpec(
        label=label,
        argv=argv,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        scope=CommandScope.TEST,
    )


def _raise_invalid_scope(scope: str, cause: str) -> None:
    raise DevCheckError(
        code="DEV_CHECK_SCOPE_INVALID",
        problem="개발 검증 범위가 올바르지 않습니다.",
        cause=f"scope={scope}, {cause}",
        impact="명령을 실행하지 않았습니다.",
        next_action="python, web 또는 workspace crate 이름을 지정하십시오.",
    )
