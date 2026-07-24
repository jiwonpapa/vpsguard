"""OPS-005/OPS-010 isolated 2GB update·restore endurance orchestration."""

from __future__ import annotations

import time
from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .protection_pilot_model import (
    Bundle,
    ProtectionPilotError,
    atomic_json,
)
from .protection_pilot_remote import (
    balloon_driver_loaded,
    domain_memory,
    ensure_balloon_driver,
    guest_text,
    remove_stage,
    restore_balloon_driver,
    service_states,
    set_domain_memory,
    snapshot_path,
    ssh,
    stage,
    wait_domain_memory,
    wait_guest_memory,
)
from .qga import GuestAgent
from .release_endurance_model import (
    ProbeAvailability,
    ProbeSample,
    ReleaseCycleResult,
    ReleaseEnduranceError,
    ReleaseEnduranceManifest,
    ReleaseEnduranceSummary,
    fail,
    public_probe_command,
)
from .release_endurance_probe import EndurancePhase, ProbeTimeline
from .runner import CommandRunner

__all__ = [
    "ProbeAvailability",
    "ProbeSample",
    "ReleaseEnduranceError",
    "ReleaseEnduranceManifest",
    "ReleaseEnduranceSummary",
    "public_probe_command",
    "run_release_endurance",
]


def run_release_endurance(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> ReleaseEnduranceSummary | None:
    """Plan or execute repeated update·restore under a continuous 100ms probe."""

    manifest = ReleaseEnduranceManifest.load(root, manifest_path)
    try:
        bundle = Bundle.verify(bundle_path)
    except ProtectionPilotError as error:
        fail("ENDURANCE_BUNDLE_INVALID", "검증된 release bundle이 필요합니다.", error.cause)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail(
            "ENDURANCE_EVIDENCE_ESCAPE",
            "endurance evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    stage_path = manifest.protection.stage_base / bundle.source_commit
    atomic_json(evidence_path.with_suffix(".plan.json"), _plan(manifest, bundle, stage_path))
    if not execute:
        return None
    _validate_execution(manifest, confirmation)

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.protection.host_alias,
        domain=manifest.protection.domain,
    )
    guest.ping()
    original_release = guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.protection.current_release_path)),
        "original release",
    )
    original_memory = domain_memory(runner, root, manifest.protection)
    if original_memory < manifest.protection.target_memory_kib:
        fail(
            "ENDURANCE_MEMORY_UNDERSIZED",
            "현재 VM memory가 endurance target보다 작습니다.",
            f"current={original_memory}, target={manifest.protection.target_memory_kib}",
        )
    services_before = service_states(guest, manifest.protection.services)
    balloon_was_loaded = balloon_driver_loaded(guest)
    phase = EndurancePhase()
    probe: ProbeTimeline | None = None
    probe_summary: dict[str, object] = {}
    cycle_results: list[ReleaseCycleResult] = []
    guest_mem_total = 0
    memory_restored = False
    balloon_restored = False
    failure: Exception | None = None
    started = time.monotonic_ns()
    try:
        stage(runner, root, manifest.protection, bundle, stage_path)
        ensure_balloon_driver(guest)
        set_domain_memory(
            runner,
            root,
            manifest.protection,
            manifest.protection.target_memory_kib,
        )
        guest_mem_total = wait_guest_memory(guest, manifest.protection.target_memory_kib)
        probe = ProbeTimeline(
            root,
            manifest,
            evidence_path.with_suffix(".probe.jsonl"),
            phase,
        )
        probe.start()
        if not probe.wait_healthy(after_samples=0):
            fail(
                "ENDURANCE_PROBE_PREFLIGHT_FAILED",
                "public probe 사전 성공을 확인하지 못했습니다.",
                "3 consecutive samples",
            )
        for cycle in range(1, manifest.cycles + 1):
            cycle_results.append(
                _run_cycle(
                    guest,
                    manifest,
                    bundle,
                    stage_path,
                    original_release,
                    services_before,
                    cycle,
                    phase,
                )
            )
            phase.set(cycle, "verify_public")
            before = probe.samples
            if not probe.wait_healthy(after_samples=before):
                fail(
                    "ENDURANCE_PUBLIC_RECOVERY_FAILED",
                    "restore 뒤 public HTTPS가 회복되지 않았습니다.",
                    f"cycle={cycle}",
                )
            outage_ms = probe.current_max_outage_ms()
            if outage_ms > manifest.max_outage_ms:
                fail(
                    "ENDURANCE_OUTAGE_BUDGET_EXCEEDED",
                    "public HTTPS 순단 예산을 초과했습니다.",
                    f"cycle={cycle}, outage_ms={outage_ms}",
                )
        phase.set(manifest.cycles, "final_readback")
        before = probe.samples
        if not probe.wait_healthy(after_samples=before):
            fail(
                "ENDURANCE_FINAL_PUBLIC_FAILED",
                "최종 public HTTPS read-back이 실패했습니다.",
                "3 consecutive samples",
            )
    except Exception as error:
        failure = error
    finally:
        if probe is not None:
            try:
                probe_summary = probe.stop()
            except Exception as error:
                failure = error
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
            and len(cycle_results) == manifest.cycles
            and memory_restored
            and balloon_restored
        ):
            remove_stage(runner, root, manifest.protection, stage_path)

    restored_release = guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.protection.current_release_path)),
        "restored release",
    )
    services_after = service_states(guest, manifest.protection.services)
    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/true",),
        label="verify guest SSH after endurance",
    )
    _require_restored(
        restored_release,
        original_release,
        services_after,
        services_before,
        memory_restored,
        balloon_restored,
    )
    if failure is not None:
        raise failure
    if int(probe_summary.get("max_outage_ms", manifest.max_outage_ms + 1)) > manifest.max_outage_ms:
        fail(
            "ENDURANCE_OUTAGE_BUDGET_EXCEEDED",
            "public HTTPS 순단 예산을 초과했습니다.",
            f"outage_ms={probe_summary.get('max_outage_ms')}",
        )
    summary = ReleaseEnduranceSummary(
        source_commit=bundle.source_commit,
        original_release=original_release,
        restored_release=restored_release,
        original_memory_kib=original_memory,
        target_memory_kib=manifest.protection.target_memory_kib,
        guest_mem_total_kib=guest_mem_total,
        balloon_driver_was_loaded=balloon_was_loaded,
        balloon_driver_restored=balloon_restored,
        cycles_requested=manifest.cycles,
        cycles_completed=len(cycle_results),
        cycles=tuple(cycle_results),
        probe=probe_summary,
        services_before=services_before,
        services_after=services_after,
        elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
    )
    atomic_json(evidence_path, summary.as_dict())
    return summary


def _run_cycle(
    guest: GuestAgent,
    manifest: ReleaseEnduranceManifest,
    bundle: Bundle,
    stage_path: PurePosixPath,
    original_release: str,
    services_before: dict[str, str],
    cycle: int,
    phase: EndurancePhase,
) -> ReleaseCycleResult:
    snapshot: str | None = None
    candidate_release = ""
    restored_release = ""
    restored_services: dict[str, str] = {}
    update_ms = 0
    restore_ms = 0
    failure: Exception | None = None
    try:
        phase.set(cycle, "update")
        started = time.monotonic_ns()
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
        update_ms = (time.monotonic_ns() - started) // 1_000_000
        if update_ms > manifest.max_update_ms:
            fail(
                "ENDURANCE_UPDATE_BUDGET_EXCEEDED",
                "release update 시간 예산을 초과했습니다.",
                f"cycle={cycle}, update_ms={update_ms}",
            )
        snapshot = snapshot_path(update.stdout)
        phase.set(cycle, "candidate_readback")
        candidate_release = guest_text(
            guest.execute(("/bin/readlink", "-f", manifest.protection.current_release_path)),
            "candidate release",
        )
        if not candidate_release.endswith(f"/{bundle.source_commit}"):
            fail(
                "ENDURANCE_RELEASE_READBACK_MISMATCH",
                "candidate release symlink가 source commit과 일치하지 않습니다.",
                f"cycle={cycle}, release={candidate_release}",
            )
        service_states(guest, manifest.protection.services)
    except Exception as error:
        failure = error
    finally:
        if snapshot is not None:
            try:
                phase.set(cycle, "restore")
                started = time.monotonic_ns()
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
                restore_ms = (time.monotonic_ns() - started) // 1_000_000
                if restore_ms > manifest.max_restore_ms:
                    fail(
                        "ENDURANCE_RESTORE_BUDGET_EXCEEDED",
                        "deployment restore 시간 예산을 초과했습니다.",
                        f"cycle={cycle}, restore_ms={restore_ms}",
                    )
            except Exception as error:
                failure = error
        phase.set(cycle, "restore_readback")
        restored_release = guest_text(
            guest.execute(("/bin/readlink", "-f", manifest.protection.current_release_path)),
            "restored release",
        )
        restored_services = service_states(guest, manifest.protection.services)
        if restored_release != original_release or restored_services != services_before:
            fail(
                "ENDURANCE_CYCLE_PRESERVATION_MISMATCH",
                "cycle 종료 상태가 시작 release·service와 일치하지 않습니다.",
                (
                    f"cycle={cycle}, release_match={restored_release == original_release}, "
                    f"services_match={restored_services == services_before}"
                ),
            )
    if failure is not None:
        raise failure
    if snapshot is None:
        fail("ENDURANCE_SNAPSHOT_MISSING", "update snapshot이 없습니다.", f"cycle={cycle}")
    return ReleaseCycleResult(
        cycle=cycle,
        snapshot=PurePosixPath(snapshot).name,
        update_ms=update_ms,
        restore_ms=restore_ms,
        candidate_release=candidate_release,
        restored_release=restored_release,
        services_restored=restored_services == services_before,
    )


def _validate_execution(
    manifest: ReleaseEnduranceManifest,
    confirmation: str | None,
) -> None:
    if confirmation != manifest.confirmation:
        fail(
            "ENDURANCE_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )
    if manifest.ca_certificate is not None and not manifest.ca_certificate.is_file():
        fail(
            "ENDURANCE_CA_MISSING",
            "public probe CA certificate가 없습니다.",
            str(manifest.ca_certificate),
        )


def _restore_memory(
    runner: CommandRunner,
    guest: GuestAgent,
    root: Path,
    manifest: ReleaseEnduranceManifest,
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
    restored_release: str,
    original_release: str,
    services_after: dict[str, str],
    services_before: dict[str, str],
    memory_restored: bool,
    balloon_restored: bool,
) -> None:
    if (
        not memory_restored
        or not balloon_restored
        or restored_release != original_release
        or services_after != services_before
    ):
        fail(
            "ENDURANCE_AUTOMATIC_RESTORE_FAILED",
            "endurance 종료 원상복구가 시작 상태와 일치하지 않습니다.",
            (
                f"release_match={restored_release == original_release}, "
                f"services_match={services_after == services_before}, "
                f"memory_restored={memory_restored}, balloon_restored={balloon_restored}"
            ),
        )


def _plan(
    manifest: ReleaseEnduranceManifest,
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
            "public_probe": manifest.probe_url,
        },
        "source_commit": bundle.source_commit,
        "stage": str(stage_path),
        "execution": {
            "cycles": manifest.cycles,
            "interval_ms": manifest.interval_ms,
            "max_outage_ms": manifest.max_outage_ms,
            "max_update_ms": manifest.max_update_ms,
            "max_restore_ms": manifest.max_restore_ms,
        },
        "steps": [
            "verify_bundle",
            "capture_release_memory_services",
            "stage_verified_bundle",
            "balloon_to_2gib",
            "start_continuous_public_probe",
            "repeat_update_candidate_readback",
            "restore_each_deployment_snapshot",
            "verify_release_services_and_public_https_each_cycle",
            "restore_original_memory_and_balloon",
            "verify_ssh_and_remove_guest_stage",
        ],
        "preserves": [
            "SSH",
            "Apache",
            "certificate",
            "site data",
            "original VPSGuard state",
            "guest balloon module state",
        ],
        "retains_versioned_release_and_snapshots": True,
        "stores_credentials": False,
        "stores_response_bodies": False,
        "stores_request_bodies": False,
    }
