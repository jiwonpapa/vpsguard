"""OPS-006 isolated 2GB Apache bypass, uninstall and exact-restore orchestration."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .errors import HarnessError
from .protection_pilot_model import Bundle, ProtectionPilotError, atomic_json
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
    stage,
    wait_domain_memory,
    wait_guest_memory,
)
from .qga import GuestAgent
from .release_endurance_model import public_probe_command
from .release_endurance_probe import EndurancePhase, ProbeTimeline
from .runner import CommandRunner, CommandScope, CommandSpec
from .uninstall_pilot_model import (
    UninstallPilotManifest,
    UninstallPilotSummary,
    fail,
)
from .uninstall_pilot_remote import (
    apache_stage_path,
    apply_apache_direction,
    capture_protected_fingerprints,
    create_deployment_snapshot,
    create_release_snapshot,
    prepare_apache_stage,
    protected_listener_ports,
    remove_apache_stage,
    remove_release_snapshot,
    require_bundle_layout,
    require_guest_paths_absent,
    require_post_uninstall,
    restore_deployment,
    restore_release_snapshot,
    run_uninstall,
    verify_release_snapshot,
    verify_staged_bundle,
)


def run_uninstall_pilot(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> UninstallPilotSummary | None:
    """Plan or execute a real Apache bypass and owned-only uninstall on the lab VM."""

    manifest = UninstallPilotManifest.load(root, manifest_path)
    try:
        bundle = Bundle.verify(bundle_path)
    except ProtectionPilotError as error:
        fail("UNINSTALL_BUNDLE_INVALID", "검증된 release bundle이 필요합니다.", error.cause)
    require_bundle_layout(bundle)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail(
            "UNINSTALL_EVIDENCE_ESCAPE",
            "uninstall evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    bundle_stage = (
        manifest.endurance.protection.stage_base
        / "ops006-uninstall"
        / bundle.source_commit
    )
    apache_stage = apache_stage_path(bundle)
    atomic_json(
        evidence_path.with_suffix(".plan.json"),
        _plan(manifest, bundle, bundle_stage, apache_stage),
    )
    if not execute:
        return None
    _validate_execution(manifest, confirmation)

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.endurance.protection.host_alias,
        domain=manifest.endurance.protection.domain,
    )
    guest.ping()
    original_release = guest_text(
        guest.execute(
            ("/bin/readlink", "-f", manifest.endurance.protection.current_release_path)
        ),
        "original release",
    )
    original_memory = domain_memory(runner, root, manifest.endurance.protection)
    if original_memory < manifest.endurance.protection.target_memory_kib:
        fail(
            "UNINSTALL_MEMORY_UNDERSIZED",
            "현재 VM memory가 uninstall target보다 작습니다.",
            f"current={original_memory}",
        )
    services_before = service_states(
        guest,
        manifest.endurance.protection.services,
    )
    protected_before = capture_protected_fingerprints(guest)
    listeners_before = protected_listener_ports(guest)
    balloon_was_loaded = balloon_driver_loaded(guest)
    original_header = _public_readback(runner, root, manifest)
    if original_header != (manifest.endurance.expected_status, True):
        fail(
            "UNINSTALL_TOPOLOGY_PREFLIGHT_FAILED",
            "시작 public 경로가 Apache guarded topology가 아닙니다.",
            repr(original_header),
        )

    phase = EndurancePhase()
    timeline: ProbeTimeline | None = None
    probe_summary: dict[str, object] = {}
    generated: set[str] = set()
    deployment_snapshot: str | None = None
    release_snapshot: str | None = None
    release_count = 0
    binary_count = 0
    stage_created = False
    apache_prepared = False
    mutation_started = False
    uninstall_started = False
    release_restored = False
    deployment_restored = False
    topology_restored = False
    memory_restored = False
    balloon_restored = False
    bypass_ms = 0
    uninstall_ms = 0
    restore_ms = 0
    reenable_ms = 0
    guest_mem_total = 0
    post_uninstall: dict[str, object] = {}
    failure: Exception | None = None
    started = time.monotonic_ns()
    try:
        require_guest_paths_absent(guest, apache_stage)
        stage(
            runner,
            root,
            manifest.endurance.protection,
            bundle,
            bundle_stage,
        )
        stage_created = True
        verify_staged_bundle(guest, bundle, bundle_stage)
        prepare_apache_stage(guest, bundle_stage, apache_stage)
        apache_prepared = True
        release_snapshot, release_count, binary_count = create_release_snapshot(
            guest,
            bundle_stage,
        )
        deployment_snapshot = create_deployment_snapshot(guest, bundle_stage)
        generated.add(deployment_snapshot)

        ensure_balloon_driver(guest)
        set_domain_memory(
            runner,
            root,
            manifest.endurance.protection,
            manifest.endurance.protection.target_memory_kib,
        )
        guest_mem_total = wait_guest_memory(
            guest,
            manifest.endurance.protection.target_memory_kib,
        )
        timeline = ProbeTimeline(
            root,
            manifest.endurance,
            evidence_path.with_suffix(".probe.jsonl"),
            phase,
        )
        timeline.start()
        if not timeline.wait_healthy(after_samples=0):
            fail(
                "UNINSTALL_PUBLIC_PREFLIGHT_FAILED",
                "public HTTPS probe 사전 성공을 확인하지 못했습니다.",
                "3 consecutive samples",
            )

        mutation_started = True
        phase.set(1, "apache_bypass")
        bypass_ms, paths = apply_apache_direction(
            guest,
            bundle_stage,
            apache_stage,
            "to-apache",
        )
        generated.update(paths)
        bypass_readback = _public_readback(runner, root, manifest)
        if bypass_readback != (manifest.endurance.expected_status, False):
            fail(
                "UNINSTALL_BYPASS_READBACK_FAILED",
                "Apache direct bypass read-back이 일치하지 않습니다.",
                repr(bypass_readback),
            )

        phase.set(1, "uninstall")
        uninstall_started = True
        uninstall_ms = run_uninstall(guest, manifest, bundle_stage)
        post_uninstall = require_post_uninstall(guest)
        post_status, post_header = _public_readback(runner, root, manifest)
        protected_post = capture_protected_fingerprints(guest)
        expected_bypass = hashlib.sha256(
            (bundle.path / "gnuboard5/apache/gnuboard5-bypass.conf").read_bytes()
        ).hexdigest()
        _require_post_preservation(
            protected_before,
            protected_post,
            expected_bypass,
        )
        if (
            post_status != manifest.endurance.expected_status
            or post_header
            or protected_listener_ports(guest) != listeners_before
        ):
            fail(
                "UNINSTALL_PUBLIC_PRESERVATION_FAILED",
                "uninstall 뒤 public HTTPS 또는 non-web listener가 보존되지 않았습니다.",
                f"status={post_status}, edge_header={post_header}",
            )
        post_uninstall.update(
            {
                "public_status": post_status,
                "edge_header_absent": not post_header,
                "configuration_preserved": True,
                "runtime_state_preserved": True,
                "certificate_preserved": True,
                "site_sentinel_preserved": True,
                "ssh_listener_preserved": True,
                "firewall_preserved": True,
            }
        )

        phase.set(1, "restore_release_tree")
        restore_release_snapshot(guest, bundle_stage, release_snapshot)
        release_restored = True
        phase.set(1, "restore_deployment")
        restore_ms, paths = restore_deployment(
            guest,
            manifest,
            bundle_stage,
            deployment_snapshot,
        )
        generated.update(paths)
        deployment_restored = True
        phase.set(1, "restore_guarded_topology")
        reenable_ms, paths = apply_apache_direction(
            guest,
            bundle_stage,
            apache_stage,
            "to-edge",
        )
        generated.update(paths)
        topology_restored = True
        before = timeline.samples
        if not timeline.wait_healthy(after_samples=before):
            fail(
                "UNINSTALL_PUBLIC_RECOVERY_FAILED",
                "restore 뒤 public HTTPS가 회복되지 않았습니다.",
                "3 consecutive samples",
            )
    except Exception as error:
        failure = error
    finally:
        if mutation_started and deployment_snapshot is not None:
            try:
                release_root = PurePosixPath(
                    "/", "usr", "local", "lib", "vps-guard", "releases"
                )
                if (
                    uninstall_started
                    and release_snapshot is not None
                    and not release_restored
                    and not _guest_path_exists(guest, release_root)
                ):
                    restore_release_snapshot(guest, bundle_stage, release_snapshot)
                    release_restored = True
                if not deployment_restored:
                    recovered_ms, paths = restore_deployment(
                        guest,
                        manifest,
                        bundle_stage,
                        deployment_snapshot,
                    )
                    restore_ms = restore_ms or recovered_ms
                    generated.update(paths)
                    deployment_restored = True
                if apache_prepared and not topology_restored:
                    recovered_ms, paths = apply_apache_direction(
                        guest,
                        bundle_stage,
                        apache_stage,
                        "to-edge",
                    )
                    reenable_ms = reenable_ms or recovered_ms
                    generated.update(paths)
                    topology_restored = True
            except Exception as error:
                failure = failure or error
        if timeline is not None:
            try:
                probe_summary = timeline.stop()
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

    restored_release = guest_text(
        guest.execute(
            ("/bin/readlink", "-f", manifest.endurance.protection.current_release_path)
        ),
        "restored release",
    )
    services_after = service_states(
        guest,
        manifest.endurance.protection.services,
    )
    protected_after = capture_protected_fingerprints(guest)
    listeners_after = protected_listener_ports(guest)
    final_public = _public_readback(runner, root, manifest)
    if release_snapshot is not None:
        verify_release_snapshot(guest, bundle_stage, release_snapshot)
    ssh(
        runner,
        root,
        manifest.endurance.protection.guest_copy_target,
        ("/bin/true",),
        label="verify guest SSH after uninstall pilot",
    )
    if (
        restored_release != original_release
        or services_after != services_before
        or protected_after != protected_before
        or listeners_after != listeners_before
        or not release_restored
        or final_public != (manifest.endurance.expected_status, True)
        or not memory_restored
        or not balloon_restored
    ):
        fail(
            "UNINSTALL_AUTOMATIC_RESTORE_FAILED",
            "uninstall pilot 종료 상태가 시작 상태와 일치하지 않습니다.",
            (
                f"release={restored_release == original_release}, "
                f"services={services_after == services_before}, "
                f"protected={protected_after == protected_before}, "
                f"listeners={listeners_after == listeners_before}, "
                f"release_tree={release_restored}, "
                f"public={final_public}, memory={memory_restored}, balloon={balloon_restored}"
            ),
        )
    if failure is not None:
        raise failure
    if int(probe_summary.get("max_outage_ms", manifest.endurance.max_outage_ms + 1)) > manifest.endurance.max_outage_ms:
        fail(
            "UNINSTALL_OUTAGE_BUDGET_EXCEEDED",
            "uninstall timeline의 public HTTPS 순단 예산을 초과했습니다.",
            f"outage_ms={probe_summary.get('max_outage_ms')}",
        )

    if release_snapshot is None:
        fail(
            "UNINSTALL_RELEASE_SNAPSHOT_MISSING",
            "uninstall release snapshot이 없습니다.",
            "snapshot=None",
        )
    remove_release_snapshot(guest, bundle_stage, release_snapshot)
    remove_apache_stage(guest, apache_stage)
    if stage_created:
        remove_stage(
            runner,
            root,
            manifest.endurance.protection,
            bundle_stage,
        )
    summary = UninstallPilotSummary(
        source_commit=bundle.source_commit,
        original_release=original_release,
        restored_release=restored_release,
        original_memory_kib=original_memory,
        target_memory_kib=manifest.endurance.protection.target_memory_kib,
        guest_mem_total_kib=guest_mem_total,
        balloon_driver_was_loaded=balloon_was_loaded,
        balloon_driver_restored=balloon_restored,
        release_directories=release_count,
        release_files=binary_count,
        bypass_ms=bypass_ms,
        uninstall_ms=uninstall_ms,
        restore_ms=restore_ms,
        reenable_ms=reenable_ms,
        public_probe=probe_summary,
        services_before=services_before,
        services_after=services_after,
        post_uninstall=post_uninstall,
        protected_fingerprints=protected_before,
        protected_listener_ports=listeners_before,
        recovery_artifacts_retained=len(generated),
        elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
    )
    atomic_json(evidence_path, summary.as_dict())
    return summary


def _public_readback(
    runner: CommandRunner,
    root: Path,
    manifest: UninstallPilotManifest,
) -> tuple[int, bool]:
    command = list(public_probe_command(manifest.endurance))
    write_index = command.index("--write-out")
    command[write_index + 1] = "\\n%{http_code}"
    command[command.index("--output") : command.index("--output") + 2] = [
        "--dump-header",
        "-",
        "--output",
        "/dev/null",
    ]
    result = runner.run(
        CommandSpec(
            label="uninstall public header read-back",
            argv=tuple(command),
            cwd=root,
            timeout_seconds=5,
            scope=CommandScope.TEST,
            max_output_bytes=65_536,
        )
    )
    lines = result.stdout.splitlines()
    try:
        status = int(lines[-1])
    except (IndexError, ValueError):
        fail("UNINSTALL_PUBLIC_OUTPUT_INVALID", "public status를 해석하지 못했습니다.", result.stdout)
    edge_header = any(line.lower().startswith("x-vps-guard:") for line in lines[:-1])
    return status, edge_header


def _require_post_preservation(
    before: dict[str, str],
    after: dict[str, str],
    expected_bypass: str,
) -> None:
    changed = [
        label
        for label, digest in before.items()
        if label != "apache_public_vhost" and after.get(label) != digest
    ]
    if after.get("apache_public_vhost") != expected_bypass or changed:
        fail(
            "UNINSTALL_PROTECTED_STATE_CHANGED",
            "uninstall이 보호 설정·인증서·사이트·SSH·방화벽을 변경했습니다.",
            f"changed={changed}, bypass_exact={after.get('apache_public_vhost') == expected_bypass}",
        )


def _guest_path_exists(guest: GuestAgent, path: PurePosixPath) -> bool:
    result = guest.execute(("/bin/test", "-e", str(path)), accepted_exit_codes=(0, 1))
    return result.exit_code == 0


def _restore_memory(
    runner: CommandRunner,
    guest: GuestAgent,
    root: Path,
    manifest: UninstallPilotManifest,
    original_memory: int,
    balloon_was_loaded: bool,
) -> tuple[bool, bool]:
    try:
        set_domain_memory(
            runner,
            root,
            manifest.endurance.protection,
            original_memory,
        )
        memory_restored = wait_domain_memory(
            runner,
            root,
            manifest.endurance.protection,
            original_memory,
        )
        balloon_restored = restore_balloon_driver(
            guest,
            was_loaded=balloon_was_loaded,
        )
    except HarnessError:
        return False, False
    return memory_restored, balloon_restored


def _validate_execution(
    manifest: UninstallPilotManifest,
    confirmation: str | None,
) -> None:
    if confirmation != manifest.confirmation:
        fail(
            "UNINSTALL_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )
    certificate = manifest.endurance.ca_certificate
    if certificate is not None and not certificate.is_file():
        fail("UNINSTALL_CA_MISSING", "public probe CA가 없습니다.", str(certificate))


def _plan(
    manifest: UninstallPilotManifest,
    bundle: Bundle,
    bundle_stage: PurePosixPath,
    apache_stage: PurePosixPath,
) -> dict[str, object]:
    parsed = urlsplit(manifest.endurance.probe_url)
    return {
        "schema_version": 1,
        "requirement_ids": ["OPS-006", "OPS-010", "OPS-011"],
        "target": {
            "domain": manifest.endurance.protection.domain,
            "private_ip": manifest.endurance.probe_ip,
            "memory_kib": manifest.endurance.protection.target_memory_kib,
            "public_port": parsed.port or 443,
            "ingress": manifest.ingress,
        },
        "bundle": {
            "source_commit": bundle.source_commit,
            "stage": str(bundle_stage),
        },
        "ephemeral_paths": {
            "apache_stage": str(apache_stage),
            "release_backup": "Rust typed uninstall-* snapshot",
        },
        "steps": [
            "verify_bundle_and_guarded_public_topology",
            "inventory_bounded_versioned_releases",
            "snapshot_owned_deployment_and_backup_release_binaries",
            "set_exact_2GB_live_memory_and_start_100ms_probe",
            "typed_apache_bypass",
            "apply_owned_only_uninstall",
            "verify_public_site_certificate_ssh_firewall_and_non_web_listeners",
            "restore_release_tree_and_typed_deployment_snapshot",
            "typed_apache_guarded_reenable",
            "verify_exact_state_and_remove_run_created_artifacts",
        ],
        "budgets": {
            "probe_interval_ms": manifest.endurance.interval_ms,
            "max_outage_ms": manifest.endurance.max_outage_ms,
            "max_uninstall_ms": manifest.max_uninstall_ms,
            "max_restore_ms": manifest.max_restore_ms,
        },
        "preserves": [
            "Apache public HTTPS",
            "certificate and private-key metadata",
            "site sentinel",
            "SSH",
            "firewall",
            "non-web listeners",
            "configuration and runtime state",
            "original versioned releases",
        ],
        "retains_typed_deployment_and_apache_recovery_snapshots": True,
        "scans_site_tree": False,
        "stores_credentials": False,
        "stores_site_content": False,
        "stores_response_bodies": False,
        "stores_request_bodies": False,
        "requires_confirmation": manifest.confirmation,
    }
