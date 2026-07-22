"""NFR-014 host-to-VM adversarial scenario planning and bounded execution."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .errors import HarnessError
from .runner import CommandResult, CommandRunner, CommandScope, CommandSpec


class VmLabError(HarnessError):
    """The VM lab manifest or one bounded scenario is invalid."""


@dataclass(frozen=True)
class VmScenario:
    """One pinned-tool scenario without credentials or request bodies."""

    name: str
    tool: str
    arguments: tuple[str, ...]
    timeout_seconds: int
    output_format: str


@dataclass(frozen=True)
class VmLabManifest:
    """Validated target, CA, image digest and scenario contract."""

    target_url: str
    target_host: str
    target_ip: str
    ca_certificate: Path
    images: dict[str, str]
    scenarios: tuple[VmScenario, ...]

    @classmethod
    def load(cls, path: Path) -> "VmLabManifest":
        """Load a strict JSON manifest and reject unsafe network or tool scope."""

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            _raise("VM_LAB_MANIFEST_READ_FAILED", "VM lab manifest를 읽지 못했습니다.", str(error))
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version",
            "target",
            "ca_certificate",
            "images",
            "scenarios",
        }:
            _raise("VM_LAB_MANIFEST_INVALID", "VM lab manifest field가 정확하지 않습니다.", str(path))
        if raw["schema_version"] != 1:
            _raise("VM_LAB_SCHEMA_UNSUPPORTED", "VM lab schema를 지원하지 않습니다.", str(raw["schema_version"]))
        target = raw["target"]
        if not isinstance(target, dict) or set(target) != {"url", "host", "ip"}:
            _raise("VM_LAB_TARGET_INVALID", "VM lab target field가 정확하지 않습니다.", repr(target))
        parsed = urlsplit(target["url"])
        if parsed.scheme != "https" or parsed.hostname != target["host"] or parsed.username:
            _raise("VM_LAB_TARGET_INVALID", "VM lab target은 credential 없는 HTTPS host여야 합니다.", target["url"])
        try:
            address = ipaddress.ip_address(target["ip"])
        except ValueError as error:
            _raise("VM_LAB_TARGET_INVALID", "VM lab target IP가 잘못됐습니다.", str(error))
        if not address.is_private:
            _raise("VM_LAB_TARGET_PUBLIC", "VM lab은 private target만 허용합니다.", str(address))
        certificate = Path(raw["ca_certificate"])
        if not certificate.is_absolute() or certificate.name.endswith("-key.pem"):
            _raise("VM_LAB_CA_INVALID", "공개 CA certificate 절대 경로만 허용합니다.", str(certificate))
        images = raw["images"]
        if not isinstance(images, dict) or not images:
            _raise("VM_LAB_IMAGES_INVALID", "VM lab image allowlist가 비어 있습니다.", repr(images))
        for name, image in images.items():
            digest = image.rsplit("@sha256:", maxsplit=1)
            if not isinstance(name, str) or len(digest) != 2 or len(digest[1]) != 64:
                _raise("VM_LAB_IMAGE_UNPINNED", "모든 VM lab image는 SHA-256 digest로 고정해야 합니다.", str(image))
            if not all(character in "0123456789abcdef" for character in digest[1]):
                _raise("VM_LAB_IMAGE_UNPINNED", "VM lab image digest가 lowercase hex가 아닙니다.", str(image))
        scenarios: list[VmScenario] = []
        for raw_scenario in raw["scenarios"]:
            if not isinstance(raw_scenario, dict) or set(raw_scenario) != {
                "name",
                "tool",
                "arguments",
                "timeout_seconds",
                "output_format",
            }:
                _raise("VM_LAB_SCENARIO_INVALID", "VM lab scenario field가 정확하지 않습니다.", repr(raw_scenario))
            arguments = raw_scenario["arguments"]
            if (
                raw_scenario["tool"] not in images
                or not isinstance(arguments, list)
                or not arguments
                or any(not isinstance(value, str) or any(control in value for control in "\x00\r\n") for value in arguments)
                or not isinstance(raw_scenario["timeout_seconds"], int)
                or not 1 <= raw_scenario["timeout_seconds"] <= 300
                or raw_scenario["output_format"] not in {"json", "text"}
            ):
                _raise("VM_LAB_SCENARIO_INVALID", "VM lab scenario 계약이 잘못됐습니다.", repr(raw_scenario))
            scenarios.append(
                VmScenario(
                    name=raw_scenario["name"],
                    tool=raw_scenario["tool"],
                    arguments=tuple(arguments),
                    timeout_seconds=raw_scenario["timeout_seconds"],
                    output_format=raw_scenario["output_format"],
                )
            )
        return cls(
            target_url=target["url"],
            target_host=target["host"],
            target_ip=str(address),
            ca_certificate=certificate,
            images=dict(images),
            scenarios=tuple(scenarios),
        )

    def command(self, scenario: VmScenario, root: Path, output: Path) -> CommandSpec:
        """Create one argv-only Docker command with a pinned image and bounded output."""

        if scenario not in self.scenarios:
            _raise("VM_LAB_SCENARIO_FOREIGN", "manifest 밖 scenario를 실행할 수 없습니다.", scenario.name)
        argv = (
            "docker",
            "run",
            "--rm",
            "--add-host",
            f"{self.target_host}:{self.target_ip}",
            "--volume",
            f"{self.ca_certificate}:/lab-ca/rootCA.pem:ro",
            "--env",
            "SSL_CERT_FILE=/lab-ca/rootCA.pem",
            self.images[scenario.tool],
            *tuple(
                value.replace("{target_url}", self.target_url).replace("{target_host}", self.target_host)
                for value in scenario.arguments
            ),
        )
        return CommandSpec(
            label=f"vm-lab {scenario.name}",
            argv=argv,
            cwd=root,
            timeout_seconds=scenario.timeout_seconds,
            scope=CommandScope.TEST,
            stdout_path=output,
            max_output_bytes=4_194_304,
        )


def run_vm_lab(
    root: Path,
    manifest_path: Path,
    evidence: Path,
    *,
    execute: bool,
    scenario_name: str | None = None,
) -> tuple[CommandResult, ...]:
    """Plan or execute selected scenarios without mutating the target VM."""

    manifest = VmLabManifest.load(manifest_path)
    scenarios = manifest.scenarios
    if scenario_name is not None:
        scenarios = tuple(scenario for scenario in scenarios if scenario.name == scenario_name)
        if not scenarios:
            _raise("VM_LAB_SCENARIO_UNKNOWN", "요청한 VM lab scenario가 없습니다.", scenario_name)
    evidence = evidence.resolve(strict=False)
    if not evidence.is_relative_to(root.resolve()):
        _raise("VM_LAB_EVIDENCE_ESCAPE", "VM lab evidence는 repository 아래여야 합니다.", str(evidence))
    plan = {
        "schema_version": 1,
        "target": {"url": manifest.target_url, "host": manifest.target_host, "ip": manifest.target_ip},
        "scenarios": [
            {
                "name": scenario.name,
                "tool": scenario.tool,
                "timeout_seconds": scenario.timeout_seconds,
                "output_format": scenario.output_format,
            }
            for scenario in scenarios
        ],
        "stores_credentials": False,
        "stores_request_bodies": False,
    }
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not execute:
        return ()
    runner = CommandRunner()
    results: list[CommandResult] = []
    for scenario in scenarios:
        results.append(
            runner.run(
                manifest.command(
                    scenario,
                    root,
                    evidence / f"{scenario.name}.{scenario.output_format}",
                )
            )
        )
    return tuple(results)


def public_probe_command(manifest: VmLabManifest) -> tuple[str, ...]:
    """Build the body-free curl argv used by the 100 ms public probe timeline."""

    parsed = urlsplit(manifest.target_url)
    port = parsed.port or 443
    return (
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}\t%{time_total}",
        "--max-time",
        "2",
        "--cacert",
        str(manifest.ca_certificate),
        "--resolve",
        f"{manifest.target_host}:{port}:{manifest.target_ip}",
        manifest.target_url,
    )


def run_public_probe_timeline(
    root: Path,
    manifest_path: Path,
    evidence: Path,
    *,
    duration_seconds: int,
    interval_ms: int = 100,
) -> dict[str, int]:
    """Record status and latency only while an independent VM mutation runs."""

    manifest = VmLabManifest.load(manifest_path)
    evidence = evidence.resolve(strict=False)
    if not evidence.is_relative_to(root.resolve()):
        _raise("VM_LAB_EVIDENCE_ESCAPE", "VM lab evidence는 repository 아래여야 합니다.", str(evidence))
    if not 1 <= duration_seconds <= 300 or not 100 <= interval_ms <= 5_000:
        _raise(
            "VM_LAB_PROBE_BOUNDS_INVALID",
            "public probe duration 또는 interval이 허용 범위 밖입니다.",
            f"duration_seconds={duration_seconds}, interval_ms={interval_ms}",
        )
    evidence.parent.mkdir(parents=True, exist_ok=True)
    command = public_probe_command(manifest)
    started = time.monotonic()
    deadline = started + duration_seconds
    sequence = 0
    failures = 0
    with evidence.open("w", encoding="utf-8") as stream:
        while time.monotonic() < deadline:
            scheduled = started + sequence * interval_ms / 1_000
            remaining = scheduled - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            sample_started = time.monotonic()
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            fields = completed.stdout.strip().split("\t", maxsplit=1)
            status = int(fields[0]) if fields and fields[0].isdigit() else 0
            if completed.returncode != 0 or not 200 <= status < 500:
                failures += 1
            sample = {
                "schema_version": 1,
                "sequence": sequence,
                "timestamp": datetime.now(UTC).isoformat(),
                "scheduled_ms": sequence * interval_ms,
                "elapsed_ms": round((time.monotonic() - sample_started) * 1_000, 3),
                "http_status": status,
                "curl_exit": completed.returncode,
            }
            stream.write(json.dumps(sample, ensure_ascii=False, separators=(",", ":")) + "\n")
            stream.flush()
            sequence += 1
    return {"samples": sequence, "failures": failures}


def _raise(code: str, problem: str, cause: str) -> None:
    raise VmLabError(
        code=code,
        problem=problem,
        cause=cause,
        impact="VM 대상 변경과 이후 공격 scenario는 실행하지 않았습니다.",
        next_action="private target, 공개 CA, digest와 bounded argv를 확인하십시오.",
    )
