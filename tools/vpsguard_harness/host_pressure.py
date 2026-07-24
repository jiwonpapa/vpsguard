"""DET-014 isolated 2GB CPU pressure and automatic recovery orchestration."""

from __future__ import annotations

import json
import time
from pathlib import Path, PurePosixPath

from .host_pressure_model import HostPressureError, HostPressureManifest, fail
from .host_pressure_remote import (
    remove_pressure_stage,
    require_pressure_restored,
    restore_pressure_memory,
    stage_pressure_probe,
)
from .protection_pilot_model import Bundle, ProtectionPilotError, atomic_json
from .protection_pilot_remote import (
    balloon_driver_loaded,
    domain_memory,
    ensure_balloon_driver,
    guest_text,
    service_states,
    set_domain_memory,
    snapshot_path,
    ssh,
    wait_guest_memory,
)
from .qga import GuestAgent
from .release_endurance_probe import EndurancePhase, ProbeTimeline
from .runner import CommandRunner

__all__ = [
    "HostPressureError",
    "HostPressureManifest",
    "Bundle",
    "run_host_pressure",
]


def run_host_pressure(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> dict[str, object] | None:
    """Plan or run bounded CPU pressure with `/proc`, API and public evidence."""

    manifest = HostPressureManifest.load(root, manifest_path)
    try:
        bundle = Bundle.verify(bundle_path)
    except ProtectionPilotError as error:
        fail("PRESSURE_BUNDLE_INVALID", "검증된 release bundle이 필요합니다.", error.cause)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail(
            "PRESSURE_EVIDENCE_ESCAPE",
            "pressure evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    stage_path = (
        manifest.protection.stage_base
        / "det014-host-pressure"
        / bundle.source_commit
    )
    atomic_json(
        evidence_path.with_suffix(".plan.json"),
        _plan(manifest, bundle, stage_path),
    )
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
    snapshot: str | None = None
    candidate_release = ""
    guest_mem_total = 0
    deployment_restored = False
    memory_restored = False
    balloon_restored = False
    failure: Exception | None = None
    started = time.monotonic_ns()
    try:
        stage_pressure_probe(runner, root, manifest, bundle, stage_path)
        update = guest.execute(
            (
                "/bin/bash",
                f"{stage_path}/bundle/scripts/update-release.sh",
                "--apply",
                f"{stage_path}/bundle",
            ),
            environment=(
                "LANG=C",
                "VPS_GUARD_UPDATE_CONFIRM=update-with-rollback",
                f"VPS_GUARD_EDGE_HOST={manifest.protection.edge_host}",
            ),
            timeout_seconds=60,
        )
        snapshot = snapshot_path(update.stdout)
        candidate_release = guest_text(
            guest.execute(
                ("/bin/readlink", "-f", manifest.protection.current_release_path)
            ),
            "candidate release",
        )
        if not candidate_release.endswith(f"/{bundle.source_commit}"):
            fail(
                "PRESSURE_RELEASE_READBACK_MISMATCH",
                "candidate release symlink가 source commit과 일치하지 않습니다.",
                candidate_release,
            )
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
        if snapshot is not None:
            try:
                guest.execute(
                    (
                        "/bin/bash",
                        f"{stage_path}/bundle/scripts/deployment-state.sh",
                        "--restore",
                        snapshot,
                    ),
                    environment=(
                        "LANG=C",
                        "VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot",
                    ),
                    timeout_seconds=30,
                )
                deployment_restored = True
            except Exception as error:
                failure = failure or error
        memory_restored, balloon_restored = restore_pressure_memory(
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
            and deployment_restored
            and memory_restored
            and balloon_restored
        ):
            remove_pressure_stage(runner, root, manifest, stage_path)

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
    require_pressure_restored(
        original_release,
        restored_release,
        services_before,
        services_after,
        deployment_restored,
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
        "source_commit": bundle.source_commit,
        "source_release": original_release,
        "candidate_release": candidate_release,
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


def _plan(
    manifest: HostPressureManifest,
    bundle: Bundle,
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
        "source_commit": bundle.source_commit,
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
            "stage_verified_bundle_and_fixed_pressure_probe",
            "update_with_snapshot_rollback",
            "balloon_to_2gib",
            "start_continuous_public_probe",
            "recover_normal_baseline",
            "run_fixed_cpu_workers_and_expensive_route",
            "compare_proc_and_control_resource",
            "observe_watch_local_recovering_normal",
            "restore_deployment_snapshot",
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
