"""TLS-002 isolated 2GB supervisor reload and connection-drain orchestration."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path, PurePosixPath

from .protection_pilot_model import Bundle, ProtectionPilotError, atomic_json
from .protection_pilot_remote import (
    balloon_driver_loaded,
    domain_memory,
    ensure_balloon_driver,
    service_states,
    set_domain_memory,
    ssh,
    wait_guest_memory,
)
from .qga import GuestAgent
from .release_endurance_model import ReleaseEnduranceManifest
from .release_endurance_probe import EndurancePhase, ProbeTimeline
from .runner import CommandRunner, RunningCommand
from .tls_reload_local import (
    TUNNEL_IP,
    close_tunnel,
    generate_certificates,
    open_tunnel,
)
from .tls_reload_model import TlsReloadManifest, TlsReloadSummary, fail
from .tls_reload_probe import (
    PersistentTlsConnection,
    TlsProbeTimeline,
    certificate_fingerprint,
    wait_for_fingerprint,
)
from .tls_reload_remote import (
    TEST_SERVICE,
    install_probe,
    remove_probe,
    remove_stage,
    require_guest_paths_absent,
    require_stage_absent,
    restore_memory,
    stage_fixture,
    stage_reload_command,
    supervisor_pid,
    verify_installed_probe,
    verify_remote_binaries,
    wait_service_active,
    wait_worker_count,
)


def run_tls_reload(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> TlsReloadSummary | None:
    """Plan or execute one 2GB graceful certificate reload with exact restore."""

    manifest = TlsReloadManifest.load(root, manifest_path)
    public_manifest = ReleaseEnduranceManifest.load(
        root,
        root / "tests/vm/gnuboard5-release-endurance.json",
    )
    try:
        bundle = Bundle.verify(bundle_path)
    except ProtectionPilotError as error:
        fail(
            "TLS_RELOAD_BUNDLE_INVALID",
            "검증된 x86_64 release bundle이 필요합니다.",
            error.cause,
        )
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root.resolve()):
        fail(
            "TLS_RELOAD_EVIDENCE_ESCAPE",
            "TLS reload evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    stage_path = (
        PurePosixPath("/home/gnuboard5/vpsguard-tls002-reload")
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
            "TLS_RELOAD_CONFIRMATION_REQUIRED",
            "격리 VM 확인 문자열이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )

    runner = CommandRunner()
    guest = GuestAgent(
        runner,
        root,
        host_alias=manifest.protection.host_alias,
        domain=manifest.protection.domain,
    )
    guest.ping()
    original_memory = domain_memory(runner, root, manifest.protection)
    if original_memory < manifest.protection.target_memory_kib:
        fail(
            "TLS_RELOAD_MEMORY_UNDERSIZED",
            "현재 VM memory가 2GB target보다 작습니다.",
            f"current={original_memory}",
        )
    services_before = service_states(guest, manifest.protection.services)
    balloon_was_loaded = balloon_driver_loaded(guest)
    require_stage_absent(guest, stage_path)
    require_guest_paths_absent(guest)

    guest_mem_total = 0
    balloon_restored = False
    memory_restored = False
    tls_timeline: TlsProbeTimeline | None = None
    public_timeline: ProbeTimeline | None = None
    persistent: PersistentTlsConnection | None = None
    tls_probe_summary: dict[str, object] = {}
    public_probe_summary: dict[str, object] = {}
    failure: Exception | None = None
    service_installed = False
    stage_created = False
    tunnel: RunningCommand | None = None
    started = time.monotonic_ns()
    result_fields: dict[str, object] = {}
    try:
        with tempfile.TemporaryDirectory(
            prefix="vpsguard-tls-reload-",
            dir="/tmp",
        ) as directory:
            fixture = Path(directory)
            generate_certificates(runner, root, fixture, manifest.probe_host)
            stage_created = True
            stage_fixture(runner, root, manifest, bundle, stage_path, fixture)
            verify_remote_binaries(guest, bundle, stage_path)
            service_installed = True
            install_probe(guest, stage_path)
            verify_installed_probe(guest)
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
            guest.execute(
                ("/bin/systemctl", "start", TEST_SERVICE),
                timeout_seconds=20,
            )
            wait_service_active(guest)
            tunnel = open_tunnel(runner, root, manifest)

            ca_bundle = fixture / "ca-bundle.pem"
            tls_timeline = TlsProbeTimeline(
                root,
                manifest,
                ca_bundle,
                evidence_path.with_suffix(".tls-probe.jsonl"),
                connect_ip=TUNNEL_IP,
            )
            public_timeline = ProbeTimeline(
                root,
                public_manifest,
                evidence_path.with_suffix(".public-probe.jsonl"),
                EndurancePhase(),
                interval_ms=1_000,
            )
            tls_timeline.start()
            public_timeline.start()
            if not tls_timeline.wait_healthy(after_samples=0):
                fail(
                    "TLS_RELOAD_PROBE_PREFLIGHT_FAILED",
                    "격리 TLS listener가 안정되지 않았습니다.",
                    "five samples",
                )
            if not public_timeline.wait_healthy(after_samples=0):
                fail(
                    "TLS_RELOAD_PUBLIC_PREFLIGHT_FAILED",
                    "기존 public HTTPS가 안정되지 않았습니다.",
                    "three samples",
                )

            initial_sha256 = certificate_fingerprint(
                fixture / "initial-cert.pem"
            )
            renewed_sha256 = certificate_fingerprint(
                fixture / "renewed-cert.pem"
            )
            persistent = PersistentTlsConnection(
                manifest,
                ca_bundle,
                connect_ip=TUNNEL_IP,
            )
            if persistent.certificate_sha256 != initial_sha256:
                fail(
                    "TLS_RELOAD_INITIAL_STATE_MISMATCH",
                    "초기 listener 인증서가 fixture와 다릅니다.",
                    persistent.certificate_sha256,
                )
            persistent.start_inflight_request()
            supervisor_pid_before = supervisor_pid(guest)
            reload_started = time.monotonic_ns()
            guest.execute(
                stage_reload_command(manifest),
                timeout_seconds=20,
            )
            guest.execute(
                ("/bin/systemctl", "reload", TEST_SERVICE),
                timeout_seconds=20,
            )
            wait_worker_count(
                guest,
                supervisor_pid_before,
                expected=2,
                timeout_seconds=12,
            )
            served_sha256 = wait_for_fingerprint(
                manifest,
                ca_bundle,
                renewed_sha256,
                connect_ip=TUNNEL_IP,
            )
            wait_remaining = manifest.drain_wait_seconds - (
                time.monotonic_ns() - reload_started
            ) / 1_000_000_000
            if wait_remaining > 0:
                time.sleep(wait_remaining)
            status_after = persistent.finish_inflight_request()
            connection_reused = persistent.is_same_open_socket
            persistent.close()
            persistent = None
            if not 200 <= status_after < 500 or not connection_reused:
                fail(
                    "TLS_RELOAD_INFLIGHT_REQUEST_FAILED",
                    "reload 전에 시작한 요청이 기존 worker drain 중 완료되지 않았습니다.",
                    f"status={status_after}, reused={connection_reused}",
                )
            wait_worker_count(
                guest,
                supervisor_pid_before,
                expected=1,
                timeout_seconds=50,
            )
            worker_drain_ms = (
                time.monotonic_ns() - reload_started
            ) // 1_000_000
            supervisor_pid_after = supervisor_pid(guest)
            if supervisor_pid_after != supervisor_pid_before:
                fail(
                    "TLS_RELOAD_SUPERVISOR_RESTARTED",
                    "certificate reload 중 systemd main PID가 바뀌었습니다.",
                    f"before={supervisor_pid_before}, after={supervisor_pid_after}",
                )
            result_fields = {
                "supervisor_pid_before": supervisor_pid_before,
                "supervisor_pid_after": supervisor_pid_after,
                "initial_certificate_sha256": initial_sha256,
                "renewed_certificate_sha256": renewed_sha256,
                "served_certificate_sha256": served_sha256,
                "inflight_request_started_before_reload": True,
                "inflight_connection_reused": connection_reused,
                "inflight_status_after_reload": status_after,
                "worker_drain_ms": worker_drain_ms,
            }
    except Exception as error:
        failure = error
    finally:
        if persistent is not None:
            persistent.close()
        if tls_timeline is not None:
            try:
                tls_probe_summary = tls_timeline.stop()
            except Exception as error:
                failure = failure or error
        if public_timeline is not None:
            try:
                public_probe_summary = public_timeline.stop()
            except Exception as error:
                failure = failure or error
        if tunnel is not None:
            try:
                close_tunnel(tunnel, manifest.probe_port)
            except Exception as error:
                failure = failure or error
        if service_installed:
            try:
                remove_probe(guest)
            except Exception as error:
                failure = failure or error
        memory_restored, balloon_restored = restore_memory(
            runner,
            guest,
            root,
            manifest,
            original_memory,
            balloon_was_loaded,
        )
        if stage_created:
            try:
                remove_stage(runner, root, manifest, stage_path)
            except Exception as error:
                failure = failure or error

    services_after = service_states(guest, manifest.protection.services)
    ssh(
        runner,
        root,
        manifest.protection.guest_copy_target,
        ("/bin/true",),
        label="verify guest SSH after TLS reload",
    )
    if (
        services_after != services_before
        or not memory_restored
        or not balloon_restored
    ):
        fail(
            "TLS_RELOAD_RESTORE_MISMATCH",
            "TLS reload 뒤 VM 원상복구가 정확하지 않습니다.",
            f"memory={memory_restored}, balloon={balloon_restored}",
        )
    if failure is not None:
        raise failure
    for label, probe in (
        ("tls", tls_probe_summary),
        ("public", public_probe_summary),
    ):
        if probe.get("failures") != 0 or probe.get("max_outage_ms") != 0:
            fail(
                "TLS_RELOAD_OUTAGE_DETECTED",
                "certificate reload 중 HTTPS 실패가 발생했습니다.",
                f"{label}={probe}",
            )
    summary = TlsReloadSummary(
        source_commit=bundle.source_commit,
        original_memory_kib=original_memory,
        target_memory_kib=manifest.protection.target_memory_kib,
        guest_mem_total_kib=guest_mem_total,
        balloon_driver_was_loaded=balloon_was_loaded,
        balloon_driver_restored=balloon_restored,
        tls_probe=tls_probe_summary,
        public_probe=public_probe_summary,
        services_before=services_before,
        services_after=services_after,
        elapsed_ms=(time.monotonic_ns() - started) // 1_000_000,
        **result_fields,
    )
    atomic_json(evidence_path, summary.as_dict())
    return summary


def _plan(
    manifest: TlsReloadManifest,
    bundle: Bundle,
    stage_path: PurePosixPath,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "requirement_ids": ["TLS-002", "TLS-004", "TLS-005", "OPS-010"],
        "target": {
            "domain": manifest.protection.domain,
            "private_ip": manifest.probe_ip,
            "memory_kib": manifest.protection.target_memory_kib,
            "stage": str(stage_path),
            "test_listener": manifest.probe_port,
            "transport": "SSH local forwarding to guest loopback",
        },
        "bundle": {
            "source_commit": bundle.source_commit,
            "path": str(bundle.path),
        },
        "steps": [
            "verify_bundle_and_pristine_test_paths",
            "generate_ephemeral_two-certificate_fixture",
            "install_executable_outside_noexec_runtime",
            "set_exact_2GB_live_memory",
            "start_isolated_supervisor_listener",
            "open_isolated_SSH_local_forward",
            "start_100ms_test_and_public_probes",
            "start_one_bounded_inflight_TLS_request_without_evidence_body",
            "stage_renewed_certificate_and_reload",
            "verify_new_fingerprint_and_old_connection_drain",
            "wait_old_worker_exit",
            "remove_test_unit_files_and_restore_memory",
        ],
        "budgets": {
            "probe_interval_ms": manifest.interval_ms,
            "public_preservation_interval_ms": 1_000,
            "max_outage_ms": manifest.max_outage_ms,
            "drain_wait_seconds": manifest.drain_wait_seconds,
        },
        "preserves": [
            "public_80_443",
            "Apache",
            "active_VPSGuard",
            "SSH",
            "certbot",
        ],
        "stores_credentials": False,
        "stores_request_bodies": False,
        "requires_confirmation": manifest.confirmation,
    }
