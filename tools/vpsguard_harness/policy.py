"""Role-based Python, Rust and Shell harness ownership policy gate."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from .errors import HarnessError
from .runner import CommandRunner, CommandScope, CommandSpec

NEW_SHELL_MAX_LINES = 40
PROTECTED_PREFIXES = (
    "/" + "etc/",
    "/" + "usr/",
    "/" + "var/lib/",
    "/" + "var/backups/",
)
FORBIDDEN_OS_CALLS = {"system", "popen"}
FORBIDDEN_SUBPROCESS_CALLS = {"call", "check_call", "check_output", "getoutput", "getstatusoutput", "Popen", "run"}


class PolicyError(HarnessError):
    """Harness implementation violates the role-based language boundary."""


def validate_language_policy(root: Path) -> None:
    """Reject unsafe Python execution and Shell growth beyond the ratchet."""

    violations = [*_validate_python(root), *_validate_shell(root)]
    if violations:
        raise PolicyError(
            code="HARNESS_LANGUAGE_POLICY_FAILED",
            problem="하네스 주력 언어 경계를 통과하지 못했습니다.",
            cause="; ".join(violations),
            impact="새로운 문자열 명령·root mutation 또는 Shell 상태 머신 증가를 허용하지 않았습니다.",
            next_action="Python 공통 runner, Rust typed adapter 또는 40줄 이하 Shell wrapper 경계로 수정하십시오.",
        )


def _validate_python(root: Path) -> list[str]:
    violations: list[str] = []
    package = root / "tools/vpsguard_harness"
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(root)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for imported in _top_level_imports(node):
                    if imported not in sys.stdlib_module_names and imported != "tools":
                        violations.append(f"{relative}: non-stdlib Python dependency {imported}")
            if isinstance(node, ast.Call):
                if any(keyword.arg == "shell" and _is_true(keyword.value) for keyword in node.keywords):
                    violations.append(f"{relative}:{node.lineno}: shell=True is forbidden")
                owner, name = _call_name(node.func)
                if owner == "os" and name in FORBIDDEN_OS_CALLS:
                    violations.append(f"{relative}:{node.lineno}: os.{name} is forbidden")
                if path.name != "runner.py" and owner == "subprocess" and name in FORBIDDEN_SUBPROCESS_CALLS:
                    violations.append(f"{relative}:{node.lineno}: subprocess.{name} must use CommandRunner")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith(PROTECTED_PREFIXES):
                    violations.append(f"{relative}:{node.lineno}: protected production path is forbidden")
    return violations


def _validate_shell(root: Path) -> list[str]:
    baseline_path = root / "tools/harness-shell-baseline.json"
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"invalid Shell baseline: {error}"]
    if baseline.get("schema_version") != 1 or not isinstance(baseline.get("files"), dict):
        return ["invalid Shell baseline schema"]
    files: dict[str, int] = baseline["files"]
    violations: list[str] = []
    current_paths = _shell_paths(root)
    for relative, path in current_paths.items():
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        limit = files.get(relative)
        if limit is None:
            if line_count > NEW_SHELL_MAX_LINES:
                violations.append(
                    f"{relative}: new Shell wrapper exceeds 40 lines ({line_count})"
                )
            continue
        if not isinstance(limit, int) or limit < 1:
            violations.append(f"{relative}: invalid baseline limit")
        elif line_count > limit:
            violations.append(f"{relative}: Shell grew from baseline {limit} to {line_count} lines")
    stale = sorted(set(files) - set(current_paths))
    violations.extend(f"{relative}: stale Shell baseline entry" for relative in stale)
    return violations


def _shell_paths(root: Path) -> dict[str, Path]:
    """Return repository-owned Shell files, falling back to all fixture files outside Git."""

    if not (root / ".git").exists():
        paths = sorted((root / "scripts").rglob("*.sh"))
    else:
        result = CommandRunner().run(
            CommandSpec(
                label="tracked shell inventory",
                argv=("git", "ls-files", "--cached", "--", "scripts"),
                cwd=root,
                timeout_seconds=10,
                scope=CommandScope.GOVERNANCE,
            )
        )
        paths = [root / relative for relative in result.stdout.splitlines() if relative.endswith(".sh")]
    return {str(path.relative_to(root)): path for path in paths}


def _top_level_imports(node: ast.Import | ast.ImportFrom) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(name.name.split(".", maxsplit=1)[0] for name in node.names)
    if node.level > 0 or node.module is None:
        return ()
    return (node.module.split(".", maxsplit=1)[0],)


def _call_name(node: ast.expr) -> tuple[str | None, str | None]:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None, None


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True
