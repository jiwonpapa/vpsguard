"""DET-014 isolated 2GB CPU pressure and automatic recovery orchestration."""

from __future__ import annotations

import json
import time
from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .host_pressure_model import HostPressureError, HostPressureManifest, fail
from .protection_pilot_model import atomic_json
from .protection_pilot_remote import (
    balloon_driver_loaded,
    domain_memory,
    ensure_balloon_driver,
    guest_text,
    remove_stage,
    restore_balloon_driver,
    service_states,
    set_domain_memory,
    ssh,
    wait_domain_memory,
    wait_guest_memory,
)
from .qga import GuestAgent
from .release_endurance_probe import EndurancePhase, ProbeTimeline
from .runner import CommandRunner, CommandScope, CommandSpec

__all__ = [
    "HostPressureError",
    "HostPressureManifest",
    "run_host_pressure",
]


def run_host_pressure(
    root: Path,
    manifest_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> dict[str, object] | None:
    """Plan or run bounded CPU pressure with `/proc`, API and public evidence."""

    manifest = HostPressureManifest.load(root, manifest_path)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail(
            "PRESSURE_EVIDENCE_ESCAPE",
            "pressure evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    stage_path = manifest.protection.stage_base
    atomic_json(evidence_path.with_suffix(".plan.json"), _plan(manifest, stage_path))
    if not execute:
        return None
    if confirmation != manifest.confirmation:
        fail(
            "PRESSURE_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )
    if manifest.ca_certificate is not None and not manifest.ca_certificate.is_file():
        fail(
            "PRESSURE_CA_MISSING",
            "public probe CA certificate가 없습니다.",
            str(manifest.ca_certificate),
        )

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.protection.host_alias,
        domain=manifest.protection.domain,
    )
    guest.ping()
    original_release = guest_text(
        guest.execute(
            ("/bin/readlink", "-f", manifest.protection.current_release_path)
        ),
        "original release",
    )
    original_memory = domain_memory(runner, root, manifest.protection)
    if original_memory < manifest.protection.target_memory_kib:
        fail(
            "PRESSURE_MEMORY_UNDERSIZED",
            "현재 VM memory가 pressure target보다 작습니다.",
            f"current={original_memory}, target={manifest.protection.target_memory_kib}",
        )
    services_before = service_states(guest, manifest.protection.services)
    balloon_was_loaded = balloon_driver_loaded(guest)
    phase = EndurancePhase()
    public_probe: ProbeTimeline | None = None
    public_summary: dict[str, object] = {}
    pressure_summary: dict[str, object] = {}
    guest_mem_total = 0
    memory_restored = False
    balloon_restored = False
    failure: Exception | None = None
    started = time.monotonic_ns()
    try:
        _stage_probe(runner, root, manifest, stage_path)
        ensure_balloon_driver(guest)
        set_domain_memory(
            runner,
            root,
            manifest.protection,
            manifest.protection.target_memory_kib,
        )
        guest_mem_total = wait_guest_memory(
            guest,
            manifest.protection.target_memory_kib,
        )
        public_probe = ProbeTimeline(
            root,
            manifest,
            evidence_path.with_suffix(".probe.jsonl"),
            phase,
        )
        public_probe.start()
        if not public_probe.wait_healthy(after_samples=0):
            fail(
                "PRESSURE_PUBLIC_PREFLIGHT_FAILED",
                "public HTTPS 사전 성공을 확인하지 못했습니다.",
                "3 consecutive samples",
            )
        phase.set(0, "host_pressure")
        pressure_summary = _parse_pressure(
            guest.execute(
                (
                    "/bin/python3",
                    f"{stage_path}/host-pressure-probe.py",
                    "--control-url",
                    manifest.protection.control_url,
                    "--edge-url",
                    manifest.protection.edge_url,
                    "--management-host",
                    manifest.protection.management_host,
                    "--management-origin",
                    manifest.protection.management_origin,
                    "--edge-host",
                    manifest.protection.edge_host,
                    "--admin-socket",
                    manifest.protection.admin_socket,
                    "--pressure-seconds",
                    str(manifest.pressure_seconds),
                    "--recovery-timeout-seconds",
                    str(manifest.recovery_timeout_seconds),
                    "--sample-interval-ms",
                    str(manifest.sample_interval_ms),
                    "--request-interval-ms",
                    str(manifest.request_interval_ms),
                    "--cpu-workers",
                    str(manifest.cpu_workers),
                ),
                timeout_seconds=(
                    30
                    + manifest.pressure_seconds
                    + manifest.recovery_timeout_seconds
                ),
            ).stdout
        )
        phase.set(0, "final_public")
        before = public_probe.samples
        if not public_probe.wait_healthy(after_samples=before):
            fail(
                "PRESSURE_PUBLIC_RECOVERY_FAILED",
                "pressure 종료 뒤 public HTTPS가 회복되지 않았습니다.",
                "3 consecutive samples",
            )
    except Exception as error:
        failure = error
    finally:
        if public_probe is not None:
            try:
                public_summary = public_probe.stop()
            except Exception as error:
                failure = failure or error
        memory_restored, balloon_restored = _restore_memory(
            runner,
            guest,
            root,
            manifest,
            original_memory,
            balloon_was_loaded,
        )
        if (
            failure is None
            and pressure_summary.get("result") == "PASS"
            and memory_restored
            and balloon_restored
        ):
            remove_stage(runner, root, manifest.protection, stage_path)

    restored_release = guest_text(
        guest.execute(
            ("/bin/readlink", "-f", manifest.protection.current_release_path)
        ),
        "restored release",
    )
    services_after = service_states(guest, manifest.protection.services)
    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/true",),
        label="verify guest SSH after pressure",
    )
    _require_restored(
        original_release,
        restored_release,
        services_before,
        services_after,
        memory_restored,
        balloon_restored,
    )
    if failure is not None:
        raise failure
    max_outage = int(
        public_summary.get("max_outage_ms", manifest.max_outage_ms + 1)
    )
    if max_outage > manifest.max_outage_ms:
        fail(
            "PRESSURE_PUBLIC_BUDGET_EXCEEDED",
            "pressure 중 public HTTPS 순단 예산을 초과했습니다.",
            f"outage_ms={max_outage}",
        )
    summary = {
        "schema_version": 1,
        "result": "PASS",
        "source_release": original_release,
        "restored_release": restored_release,
        "original_memory_kib": original_memory,
        "target_memory_kib": manifest.protection.target_memory_kib,
        "guest_mem_total_kib": guest_mem_total,
        "balloon_driver_was_loaded": balloon_was_loaded,
        "balloon_driver_restored": balloon_restored,
        "pressure": pressure_summary,
        "public_probe": public_summary,
        "services_before": services_before,
        "services_after": services_after,
        "elapsed_ms": (time.monotonic_ns() - started) // 1_000_000,
        "original_release_restored": original_release == restored_release,
        "original_memory_restored": memory_restored,
        "stores_credentials": False,
        "stores_response_bodies": False,
        "stores_request_bodies": False,
    }
    atomic_json(evidence_path, summary)
    return summary


def _stage_probe(
    runner: CommandRunner,
    root: Path,
    manifest: HostPressureManifest,
    stage_path: PurePosixPath,
) -> None:
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
        ("/bin/mkdir", "-p", str(stage_path)),
        label="create pressure stage",
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


def _parse_pressure(output: str) -> dict[str, object]:
    try:
        value = json.loads(output.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        fail(
            "PRESSURE_OUTPUT_INVALID",
            "pressure probe JSON을 해석하지 못했습니다.",
            str(error),
        )
    summary = value.get("summary") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("result") != "PASS"
        or not isinstance(summary, dict)
        or summary.get("local_guard_observed") is not True
        or summary.get("normal_recovered") is not True
        or value.get("stores_credentials") is not False
    ):
        fail("PRESSURE_PROBE_FAILED", "pressure probe 불변조건이 실패했습니다.", repr(value))
    return value


def _restore_memory(
    runner: CommandRunner,
    guest: GuestAgent,
    root: Path,
    manifest: HostPressureManifest,
    original_memory: int,
    balloon_was_loaded: bool,
) -> tuple[bool, bool]:
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


def _require_restored(
    original_release: str,
    restored_release: str,
    services_before: dict[str, str],
    services_after: dict[str, str],
    memory_restored: bool,
    balloon_restored: bool,
) -> None:
    if (
        original_release != restored_release
        or services_before != services_after
        or not memory_restored
        or not balloon_restored
    ):
        fail(
            "PRESSURE_AUTOMATIC_RESTORE_FAILED",
            "pressure 종료 원상복구가 시작 상태와 일치하지 않습니다.",
            (
                f"release_match={original_release == restored_release}, "
                f"services_match={services_before == services_after}, "
                f"memory_restored={memory_restored}, "
                f"balloon_restored={balloon_restored}"
            ),
        )


def _plan(
    manifest: HostPressureManifest,
    stage_path: PurePosixPath,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "target": {
            "host_alias": manifest.protection.host_alias,
            "domain": manifest.protection.domain,
            "guest_copy_target": manifest.protection.guest_copy_target,
            "target_memory_kib": manifest.protection.target_memory_kib,
            "stage": str(stage_path),
        },
        "execution": {
            "pressure_seconds": manifest.pressure_seconds,
            "recovery_timeout_seconds": manifest.recovery_timeout_seconds,
            "sample_interval_ms": manifest.sample_interval_ms,
            "request_interval_ms": manifest.request_interval_ms,
            "cpu_workers": manifest.cpu_workers,
        },
        "public_probe": {
            "url": manifest.probe_url,
            "interval_ms": manifest.probe_interval_ms,
            "max_outage_ms": manifest.max_outage_ms,
        },
        "steps": [
            "capture_release_memory_services",
            "stage_fixed_pressure_probe",
            "balloon_to_2gib",
            "start_continuous_public_probe",
            "recover_normal_baseline",
            "run_fixed_cpu_workers_and_expensive_route",
            "compare_proc_and_control_resource",
            "observe_watch_local_recovering_normal",
            "restore_original_memory_and_balloon",
            "verify_release_services_ssh_public",
        ],
        "preserves": [
            "SSH",
            "Apache",
            "certificate",
            "site data",
            "release",
            "guest balloon module state",
        ],
        "stores_credentials": False,
        "stores_response_bodies": False,
        "stores_request_bodies": False,
    }
