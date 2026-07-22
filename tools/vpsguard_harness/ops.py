"""Local operations-plan, fixture and evidence orchestration."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .runner import CommandResult, CommandRunner, CommandScope, CommandSpec


class OpsHarnessError(HarnessError):
    """Operations evidence or compatibility contract failed."""


@dataclass(frozen=True)
class OpsHarnessSummary:
    """Successful command results and evidence directory."""

    results: tuple[CommandResult, ...]
    evidence_directory: Path


def run_ops_harness(root: Path) -> OpsHarnessSummary:
    """Generate bounded plan evidence and validate compatibility adapters."""

    evidence = root / "target-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    runner = CommandRunner()
    results: list[CommandResult] = []

    def execute(
        label: str,
        argv: tuple[str, ...],
        *,
        scope: CommandScope,
        output: str | None = None,
        accepted_exit_codes: tuple[int, ...] = (0,),
    ) -> CommandResult:
        result = runner.run(
            CommandSpec(
                label=label,
                argv=argv,
                cwd=root,
                timeout_seconds=180,
                scope=scope,
                stdout_path=evidence / output if output is not None else None,
                accepted_exit_codes=accepted_exit_codes,
            )
        )
        results.append(result)
        return result

    execute(
        "smoke config validation",
        ("cargo", "run", "--quiet", "-p", "guard-cli", "--", "check-config", "--config", "configs/vps-guard.smoke.toml"),
        scope=CommandScope.BUILD,
    )
    execute(
        "g7devops shadow config validation",
        ("cargo", "run", "--quiet", "-p", "guard-cli", "--", "check-config", "--config", "configs/vps-guard.g7devops.shadow.toml"),
        scope=CommandScope.BUILD,
    )
    execute(
        "operations plan",
        ("cargo", "run", "--quiet", "-p", "guard-cli", "--", "plan", "--config", "configs/vps-guard.smoke.toml"),
        scope=CommandScope.BUILD,
        output="ops-plan.json",
    )
    execute(
        "shadow deployment plan",
        ("bash", "scripts/deploy-g7devops.sh", "--plan"),
        scope=CommandScope.COMPATIBILITY,
    )
    execute(
        "deployment restore plan",
        ("bash", "scripts/restore-g7devops.sh", "--plan"),
        scope=CommandScope.COMPATIBILITY,
        output="deployment-restore-plan.txt",
    )
    execute(
        "deployment restore fixture",
        ("bash", "scripts/tests/deployment-restore-harness.sh"),
        scope=CommandScope.TEST,
    )
    execute(
        "edge ingress plan",
        ("bash", "scripts/ingress-transaction.sh", "--to-edge", "--plan"),
        scope=CommandScope.COMPATIBILITY,
        output="ingress-edge-plan.txt",
    )
    execute(
        "Nginx bypass plan",
        ("bash", "scripts/ingress-transaction.sh", "--to-nginx", "--plan"),
        scope=CommandScope.COMPATIBILITY,
        output="ingress-bypass-plan.txt",
    )
    execute(
        "release update plan",
        ("bash", "scripts/update-release.sh", "--plan"),
        scope=CommandScope.COMPATIBILITY,
        output="update-plan.txt",
    )
    execute(
        "uninstall plan",
        ("bash", "scripts/uninstall.sh", "--plan"),
        scope=CommandScope.COMPATIBILITY,
        output="uninstall-plan.txt",
    )

    _require_contains(evidence / "ops-plan.json", '"ssh"')
    _require_contains(evidence / "ops-plan.json", '"certificates"')
    _require_contains(evidence / "ops-plan.json", '"site-data"')
    _require_contains(evidence / "ingress-edge-plan.txt", "preserve: SSH, certificates, site data")
    _require_contains(evidence / "update-plan.txt", "/" + "etc/letsencrypt")
    _require_contains(
        evidence / "deployment-restore-plan.txt",
        "VPSGuard-owned binary, unit, drop-in, config, token",
    )
    _require_contains(evidence / "uninstall-plan.txt", "remove owned path: /" + "usr/local/bin/vps-guard")
    _require_contains(evidence / "uninstall-plan.txt", "remove owned nft table: inet vps_guard")

    analyzer = shutil.which("systemd-analyze")
    if analyzer is not None:
        units = tuple(str(path.relative_to(root)) for path in sorted((root / "packaging/systemd").glob("*.service")))
        result = execute(
            "systemd unit verification",
            (analyzer, "verify", *units),
            scope=CommandScope.GOVERNANCE,
            accepted_exit_codes=(0, 1),
        )
        if result.exit_code != 0:
            ignored = (
                "Command /" + "usr/local/bin/vps-guard-control is not executable: No such file or directory",
                "Command /" + "usr/local/bin/vps-guard-edge is not executable: No such file or directory",
            )
            remaining = [
                line
                for line in (result.stdout + result.stderr).splitlines()
                if not any(message in line for message in ignored)
            ]
            if remaining:
                _raise_ops("systemd unit validation failed", remaining)

    _require_contains(
        root / "packaging/systemd/vps-guard-control.service",
        "ExecStart=/" + "usr/local/bin/vps-guard-control",
    )
    _require_contains(
        root / "packaging/systemd/vps-guard-edge.service",
        "ExecStart=/" + "usr/local/bin/vps-guard-edge",
    )
    return OpsHarnessSummary(results=tuple(results), evidence_directory=evidence)


def _require_contains(path: Path, expected: str) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        _raise_ops("evidence file is unavailable", [f"path={path}, error={error}"])
    if expected not in content:
        _raise_ops("evidence contract is missing", [f"path={path}, expected={expected}"])


def _raise_ops(problem: str, details: list[str]) -> None:
    raise OpsHarnessError(
        code="OPS_HARNESS_CONTRACT_FAILED",
        problem=problem,
        cause="; ".join(details),
        impact="운영 plan과 복구 불변조건을 검증 완료로 표시하지 않았습니다.",
        next_action="후보 artifact와 compatibility adapter를 수정한 뒤 다시 실행하십시오.",
    )
