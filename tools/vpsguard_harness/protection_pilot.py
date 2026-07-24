"""UI-018 isolated 2GB VM update, policy read-back and automatic restore pilot."""

from __future__ import annotations

import time
from pathlib import Path

from .errors import HarnessError
from .protection_pilot_model import (
    Bundle,
    ProtectionPilotError,
    ProtectionPilotManifest,
    ProtectionPilotSummary,
    atomic_json,
    fail,
)
from .protection_pilot_remote import (
    domain_memory,
    guest_text,
    probe_json,
    remove_stage,
    service_states,
    set_domain_memory,
    snapshot_path,
    stage,
    wait_domain_memory,
    wait_guest_memory,
)
from .qga import GuestAgent
from .runner import CommandRunner

__all__ = [
    "Bundle",
    "ProtectionPilotError",
    "ProtectionPilotManifest",
    "ProtectionPilotSummary",
    "run_protection_pilot",
]


def run_protection_pilot(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> ProtectionPilotSummary | None:
    """Plan or execute the isolated update, 2GB policy proof and full restore."""

    manifest = ProtectionPilotManifest.load(manifest_path)
    bundle = Bundle.verify(bundle_path)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail("PILOT_EVIDENCE_ESCAPE", "pilot evidence는 repository 아래여야 합니다.", str(evidence_path))
    stage_path = manifest.stage_base / bundle.source_commit
    atomic_json(
        evidence_path.with_suffix(".plan.json"),
        _plan(manifest, bundle, stage_path=str(stage_path)),
    )
    if not execute:
        return None
    if confirmation != manifest.confirmation:
        fail(
            "PILOT_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.host_alias,
        domain=manifest.domain,
    )
    guest.ping()
    original_release = guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
        "original release",
    )
    original_memory = domain_memory(runner, root, manifest)
    if original_memory < manifest.target_memory_kib:
        fail(
            "PILOT_MEMORY_UNDERSIZED",
            "현재 VM memory가 pilot target보다 작습니다.",
            f"current={original_memory}, target={manifest.target_memory_kib}",
        )
    services_before = service_states(guest, manifest.services)
    started = time.monotonic_ns()
    snapshot: str | None = None
    candidate_release = ""
    guest_mem_total = 0
    policy: dict[str, object] = {}
    restored = False
    memory_restored = False
    try:
        stage(runner, root, manifest, bundle, stage_path)
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
                f"VPS_GUARD_EDGE_HOST={manifest.edge_host}",
            ),
            timeout_seconds=120,
        )
        snapshot = snapshot_path(update.stdout)
        candidate_release = guest_text(
            guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
            "candidate release",
        )
        if not candidate_release.endswith(f"/{bundle.source_commit}"):
            fail(
                "PILOT_RELEASE_READBACK_MISMATCH",
                "candidate release symlink가 source commit과 일치하지 않습니다.",
                candidate_release,
            )
        set_domain_memory(runner, root, manifest, manifest.target_memory_kib)
        guest_mem_total = wait_guest_memory(guest, manifest.target_memory_kib)
        policy = probe_json(
            guest.execute(
                (
                    "/bin/python3",
                    f"{stage_path}/protection-settings-probe.py",
                    "--control-url",
                    manifest.control_url,
                    "--edge-url",
                    manifest.edge_url,
                    "--management-host",
                    manifest.management_host,
                    "--management-origin",
                    manifest.management_origin,
                    "--edge-host",
                    manifest.edge_host,
                    "--admin-socket",
                    manifest.admin_socket,
                ),
                timeout_seconds=90,
            ).stdout
        )
    finally:
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
                    timeout_seconds=120,
                )
                restored = True
            except HarnessError:
                restored = False
        try:
            set_domain_memory(runner, root, manifest, original_memory)
            memory_restored = wait_domain_memory(
                runner,
                root,
                manifest,
                original_memory,
            )
        except HarnessError:
            memory_restored = False
        if restored and memory_restored:
            remove_stage(runner, root, manifest, stage_path)

    if not restored or not memory_restored:
        fail(
            "PILOT_AUTOMATIC_RESTORE_FAILED",
            "pilot 종료 복구를 완료하지 못했습니다.",
            (
                f"deployment_restored={restored}, "
                f"memory_restored={memory_restored}, stage={stage_path}"
            ),
        )
    restored_release = guest_text(
        guest.execute(("/bin/readlink", "-f", manifest.current_release_path)),
        "restored release",
    )
    services_after = service_states(guest, manifest.services)
    if restored_release != original_release or services_after != services_before:
        fail(
            "PILOT_PRESERVATION_MISMATCH",
            "pilot 종료 상태가 시작 상태와 일치하지 않습니다.",
            (
                f"release_match={restored_release == original_release}, "
                f"services_match={services_after == services_before}"
            ),
        )
    summary = ProtectionPilotSummary(
        source_commit=bundle.source_commit,
        original_release=original_release,
        candidate_release=candidate_release,
        restored_release=restored_release,
        original_memory_kib=original_memory,
        target_memory_kib=manifest.target_memory_kib,
        guest_mem_total_kib=guest_mem_total,
        policy=policy,
        services_before=services_before,
        services_after=services_after,
        elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
    )
    atomic_json(evidence_path, summary.as_dict())
    return summary


def _plan(
    manifest: ProtectionPilotManifest,
    bundle: Bundle,
    *,
    stage_path: str,
) -> dict[str, object]:
    """Build the stable dry-run contract without touching the VM."""

    return {
        "schema_version": 1,
        "target": {
            "host_alias": manifest.host_alias,
            "domain": manifest.domain,
            "guest_copy_target": manifest.guest_copy_target,
            "target_memory_kib": manifest.target_memory_kib,
        },
        "source_commit": bundle.source_commit,
        "stage": stage_path,
        "steps": [
            "verify_bundle",
            "capture_release_memory_services",
            "stage_bundle_and_probe",
            "update_with_snapshot_rollback",
            "balloon_to_2gib",
            "authenticated_policy_plan_apply_edge_readback_restore",
            "restore_deployment_snapshot",
            "restore_original_memory",
            "verify_release_and_services",
        ],
        "confirmation": manifest.confirmation,
        "preserves": ["SSH", "Apache", "certificate", "site data", "original VPSGuard state"],
        "stores_credentials": False,
        "stores_request_bodies": False,
    }
