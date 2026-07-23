"""Command-line entrypoint for VPSGuard governance and harness checks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .build_artifacts import (
    DEFAULT_BUILD_CACHE_WARNING_BYTES,
    auto_clean_build_artifacts,
    clean_build_artifacts,
    validate_build_profiles,
)
from .commit_contract import validate_commit_range
from .coverage import validate_coverage
from .dev_check import run_dev_check
from .errors import HarnessError
from .governance import validate_requirements, validate_rustdoc
from .ops import run_ops_harness
from .policy import validate_language_policy
from .release_lifecycle import run_release_lifecycle_harness
from .vm_lab import run_public_probe_timeline, run_vm_lab


def main(argv: list[str] | None = None) -> int:
    """Execute one repository-local harness command."""

    parser = argparse.ArgumentParser(prog="vpsguard-harness")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("docs", help="Rustdoc repository contract")
    requirements = subcommands.add_parser("requirements", help="requirement traceability contract")
    requirements.add_argument("--release", action="store_true")
    subcommands.add_parser("language-policy", help="Python/Rust/Shell ownership contract")
    subcommands.add_parser("ops", help="operations plan and fixture evidence")
    subcommands.add_parser(
        "release-lifecycle", help="isolated update rollback and owned-only uninstall"
    )
    build_storage = subcommands.add_parser(
        "build-storage", help="bounded Cargo artifact storage and cleanup"
    )
    build_storage_mode = build_storage.add_mutually_exclusive_group()
    build_storage_mode.add_argument("--clean", action="store_true")
    build_storage_mode.add_argument("--auto", action="store_true")
    build_storage_mode.add_argument("--check-config", action="store_true")
    build_storage.add_argument(
        "--max-gib", type=int, default=DEFAULT_BUILD_CACHE_WARNING_BYTES // 1024**3
    )
    subcommands.add_parser("coverage", help="honest LCOV workspace and production-file ratchet")
    subcommands.add_parser("commit-contract", help="requirement IDs in authored Git commits")
    dev_check = subcommands.add_parser("dev-check", help="fast check for one development scope")
    dev_check.add_argument("scope", help="python, web or one workspace crate name")
    vm_lab = subcommands.add_parser("vm-lab", help="private host-to-VM adversarial scenarios")
    vm_lab.add_argument("--manifest", type=Path, required=True)
    vm_lab.add_argument("--evidence", type=Path, required=True)
    vm_lab.add_argument("--scenario", help="run one isolated scenario by exact manifest name")
    vm_lab.add_argument("--run", action="store_true")
    vm_probe = subcommands.add_parser(
        "vm-probe-timeline", help="100 ms public status timeline during VM mutation"
    )
    vm_probe.add_argument("--manifest", type=Path, required=True)
    vm_probe.add_argument("--evidence", type=Path, required=True)
    vm_probe.add_argument("--duration-seconds", type=int, required=True)
    vm_probe.add_argument("--interval-ms", type=int, default=100)
    arguments = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]

    try:
        if arguments.command == "docs":
            validate_rustdoc(root)
            print("docs gate: PASS")
        elif arguments.command == "requirements":
            print(validate_requirements(root, release=arguments.release).display())
        elif arguments.command == "language-policy":
            validate_language_policy(root)
            print("harness language gate: PASS")
        elif arguments.command == "ops":
            summary = run_ops_harness(root)
            for result in summary.results:
                if result.stdout and result.scope.value in {"build", "test", "compatibility"}:
                    print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
                if result.stderr:
                    print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
            print("ops harness: PASS")
        elif arguments.command == "release-lifecycle":
            summary = run_release_lifecycle_harness(root)
            print(
                f"release lifecycle harness: PASS scenarios={summary.scenarios} "
                f"commands={len(summary.results)}"
            )
        elif arguments.command == "build-storage":
            validate_build_profiles(root)
            if arguments.check_config:
                print("build storage profile gate: PASS")
            elif arguments.auto:
                print(
                    auto_clean_build_artifacts(
                        root, warning_bytes=int(arguments.max_gib * 1024**3)
                    ).display()
                )
            else:
                print(clean_build_artifacts(root, apply=arguments.clean).display())
        elif arguments.command == "coverage":
            print(
                validate_coverage(
                    root,
                    root / "target-evidence/coverage/lcov.info",
                    root / "tools/coverage-baseline.toml",
                ).display()
            )
        elif arguments.command == "commit-contract":
            print(validate_commit_range(root).display())
        elif arguments.command == "dev-check":
            print(run_dev_check(root, arguments.scope).display())
        elif arguments.command == "vm-lab":
            results = run_vm_lab(
                root,
                arguments.manifest,
                arguments.evidence,
                execute=arguments.run,
                scenario_name=arguments.scenario,
            )
            print(f"vm lab: {'PASS' if arguments.run else 'PLAN'} scenarios={len(results)}")
        elif arguments.command == "vm-probe-timeline":
            summary = run_public_probe_timeline(
                root,
                arguments.manifest,
                arguments.evidence,
                duration_seconds=arguments.duration_seconds,
                interval_ms=arguments.interval_ms,
            )
            print(
                f"vm probe timeline: PASS samples={summary['samples']} failures={summary['failures']}"
            )
    except HarnessError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
