"""NFR-001 direct Nginx versus guard-edge proof on one isolated 2GiB VM."""

from __future__ import annotations

import hashlib
import shlex
import tempfile
import time
from dataclasses import asdict
from pathlib import Path, PurePosixPath

from .errors import HarnessError
from .load_regression import LoadMetrics, load_metrics
from .load_regression_vm_model import (
    VmLoadRegressionManifest,
    VmLoadRound,
    aggregate_rounds,
    atomic_json,
    fail,
    verify_k6_binary,
)
from .load_regression_vm_remote import RemoteLab, single_line, validate_stage
from .protection_pilot_model import Bundle
from .runner import CommandRunner, RunningCommand

BUNDLE_DIRECTORY = "vpsguard-bundle"


def run_vm_load_regression(
    root: Path,
    manifest_path: Path,
    bundle_path: Path,
    k6_binary: Path,
    evidence_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
) -> dict[str, object] | None:
    """Plan or execute an automatically restored 2GiB Nginx A/B measurement."""

    root = root.resolve()
    manifest = VmLoadRegressionManifest.load(manifest_path)
    bundle = Bundle.verify(bundle_path)
    k6_binary = k6_binary.resolve()
    k6_sha256 = verify_k6_binary(k6_binary, manifest.k6_sha256)
    evidence_path = evidence_path.resolve(strict=False)
    if not evidence_path.is_relative_to(root):
        fail(
            "VM_LOAD_EVIDENCE_ESCAPE",
            "VM load evidence는 repository 아래여야 합니다.",
            str(evidence_path),
        )
    guest_stage = manifest.stage_base / bundle.source_commit
    host_stage = manifest.host_stage_base / bundle.source_commit
    atomic_json(
        evidence_path.with_suffix(".plan.json"),
        _plan(manifest, bundle, guest_stage, k6_sha256),
    )
    if not execute:
        return None
    if confirmation != manifest.confirmation:
        fail(
            "VM_LOAD_CONFIRMATION_REQUIRED",
            "격리 VM 실행 확인값이 일치하지 않습니다.",
            f"expected={manifest.confirmation}",
        )

    evidence_dir = root / "target-evidence" / "nfr001-vm" / bundle.source_commit
    evidence_dir.mkdir(parents=True, exist_ok=True)
    known_hosts = evidence_dir / "known_hosts"
    known_hosts.touch(mode=0o600, exist_ok=True)
    lab = RemoteLab(CommandRunner(), root, manifest, known_hosts)
    original_memory = lab.domain_memory()
    if original_memory < manifest.target_memory_kib:
        fail(
            "VM_LOAD_MEMORY_UNDERSIZED",
            "현재 VM memory가 2GiB target보다 작습니다.",
            f"current={original_memory}, target={manifest.target_memory_kib}",
        )
    nginx_state_before = single_line(
        lab.guest(
            (_root("usr/bin/systemctl"), "is-active", manifest.nginx_service),
            label="read Nginx service state",
        ).stdout,
        "Nginx state",
    )
    if nginx_state_before != "active":
        fail("VM_LOAD_NGINX_INACTIVE", "Nginx service가 active가 아닙니다.", nginx_state_before)
    nginx_hash_before = lab.nginx_hash()
    public_status_before = lab.public_status()
    started = time.monotonic_ns()
    edge: RunningCommand | None = None
    edge_pid: int | None = None
    temp_config_installed = False
    memory_changed = False
    guest_stage_created = False
    host_stage_created = False
    rounds: list[VmLoadRound] = []
    edge_rss_kib: list[int] = []
    guest_mem_total_kib = 0
    try:
        guest_stage_created = True
        host_stage_created = True
        _stage(lab, bundle, k6_binary, guest_stage, host_stage)
        memory_changed = True
        lab.set_domain_memory(manifest.target_memory_kib)
        guest_mem_total_kib = lab.wait_guest_memory(manifest.target_memory_kib)
        temp_config_installed = True
        _install_nginx_origin(lab, guest_stage)
        _wait_direct_and_guard(lab, manifest, direct_only=True)
        edge, edge_pid = _start_edge(lab, guest_stage)
        _wait_direct_and_guard(lab, manifest, direct_only=False)
        for number in range(1, manifest.rounds + 1):
            order = ("direct", "guard") if number % 2 else ("guard", "direct")
            metrics: dict[str, LoadMetrics] = {}
            for kind in order:
                metrics[kind] = _run_k6(
                    lab,
                    host_stage,
                    evidence_dir,
                    number,
                    kind,
                )
                if kind == "guard" and edge_pid is not None:
                    edge_rss_kib.append(lab.process_rss(edge_pid))
            rounds.append(
                VmLoadRound(
                    number=number,
                    order=order,
                    direct=metrics["direct"],
                    guard=metrics["guard"],
                )
            )
    finally:
        if edge is not None:
            edge.stop(timeout_seconds=5)
        edge_stopped = _stop_remote_edge(lab, edge_pid)
        nginx_restored = _restore_nginx(lab, installed=temp_config_installed)
        memory_restored = _restore_memory(
            lab,
            original_memory,
            changed=memory_changed,
        )
        stages_removed = False
        if edge_stopped and nginx_restored and memory_restored:
            stages_removed = _remove_stages(
                lab,
                guest_stage,
                host_stage,
                guest_created=guest_stage_created,
                host_created=host_stage_created,
            )
        if not (edge_stopped and nginx_restored and memory_restored and stages_removed):
            fail(
                "VM_LOAD_AUTOMATIC_RESTORE_FAILED",
                "VM load 종료 원상복구가 완료되지 않았습니다.",
                (
                    f"edge_stopped={edge_stopped}, nginx_restored={nginx_restored}, "
                    f"memory_restored={memory_restored}, stages_removed={stages_removed}"
                ),
            )

    nginx_state_after = single_line(
        lab.guest(
            (_root("usr/bin/systemctl"), "is-active", manifest.nginx_service),
            label="read restored Nginx state",
        ).stdout,
        "restored Nginx state",
    )
    nginx_hash_after = lab.nginx_hash()
    public_status_after = lab.public_status()
    restored_memory = lab.domain_memory()
    preservation = {
        "nginx_service_restored": nginx_state_after == nginx_state_before,
        "nginx_config_restored": nginx_hash_after == nginx_hash_before,
        "public_status_restored": public_status_after == public_status_before,
        "memory_restored": restored_memory == original_memory,
        "temporary_stages_removed": True,
    }
    if not all(preservation.values()):
        fail(
            "VM_LOAD_PRESERVATION_MISMATCH",
            "Nginx public 상태 또는 VM memory가 시작 상태와 일치하지 않습니다.",
            repr(preservation),
        )

    result = aggregate_rounds(rounds)
    edge_config = _edge_config(root, manifest, guest_stage)
    report = {
        "schema_version": 1,
        "requirement": "NFR-001",
        "result": "PASS" if result.passed else "FAIL",
        "source_commit": bundle.source_commit,
        "environment": {
            "same_2gb_ubuntu_vm": True,
            "domain": manifest.domain,
            "private_ip": manifest.private_ip,
            "guest": lab.guest_metadata(),
            "host": lab.host_metadata(),
            "original_memory_kib": original_memory,
            "target_memory_kib": manifest.target_memory_kib,
            "guest_mem_total_kib": guest_mem_total_kib,
        },
        "workload": {
            "runner": f"k6 {manifest.k6_version}",
            "runner_sha256": k6_sha256,
            "vus": manifest.vus,
            "duration_seconds": manifest.duration_seconds,
            "think_time_ms": manifest.think_time_ms,
            "rounds": manifest.rounds,
            "request_host": manifest.request_host,
            "request_path": manifest.request_path,
            "benchmark_kind": "private-nginx-static-html",
            "dynamic_g7_smoke": "direct-and-guard-200",
        },
        "artifacts": {
            "edge_sha256": _sha256(bundle.path / "bin/vps-guard-edge"),
            "edge_config_sha256": _sha256_text(edge_config),
            "nginx_config_sha256": _sha256_text(_nginx_config(manifest)),
        },
        "rounds": [item.as_dict() for item in rounds],
        "budget": asdict(result),
        "edge_rss_kib": {
            "samples": edge_rss_kib,
            "max": max(edge_rss_kib) if edge_rss_kib else 0,
        },
        "preservation": preservation,
        "stores_credentials": False,
        "stores_request_bodies": False,
        "elapsed_ms": (time.monotonic_ns() - started) // 1_000_000,
    }
    atomic_json(evidence_path, report)
    if not result.passed:
        fail(
            "VM_LOAD_BUDGET_EXCEEDED",
            "2GiB direct Nginx 대비 guard-edge 성능 예산을 초과했습니다.",
            (
                f"p95_overhead={result.p95_overhead_ms:.3f}ms, "
                f"throughput_reduction={result.throughput_reduction_percent:.2f}%"
            ),
        )
    return report


def _plan(
    manifest: VmLoadRegressionManifest,
    bundle: Bundle,
    guest_stage: PurePosixPath,
    k6_sha256: str,
) -> dict[str, object]:
    """Build the stable, mutation-free execution plan."""

    return {
        "schema_version": 1,
        "requirement": "NFR-001",
        "source_commit": bundle.source_commit,
        "target": {
            "host_alias": manifest.host_alias,
            "domain": manifest.domain,
            "guest_target": manifest.guest_target,
            "target_memory_kib": manifest.target_memory_kib,
        },
        "stage": str(guest_stage),
        "k6_sha256": k6_sha256,
        "steps": [
            "capture_memory_nginx_public_state",
            "stage_verified_bundle_k6_and_fixed_configs",
            "set_exact_2gb_live_memory",
            "add_private_only_nginx_origin_listener",
            "start_unprivileged_guard_edge",
            "run_three_alternating_50vu_15s_pairs",
            "stop_edge_remove_listener_restore_memory",
            "read_back_exact_nginx_public_memory_state",
        ],
        "preserves": ["public Nginx 80/443", "PHP-FPM", "TLS", "site data"],
        "confirmation": manifest.confirmation,
    }


def _stage(
    lab: RemoteLab,
    bundle: Bundle,
    k6_binary: Path,
    guest_stage: PurePosixPath,
    host_stage: PurePosixPath,
) -> None:
    """Stage verified artifacts on the guest and off-guest load host."""

    _require_stage_absent(lab, guest_stage, guest=True)
    _require_stage_absent(lab, host_stage, guest=False)
    lab.guest(
        (_root("bin/mkdir"), "-p", str(guest_stage)),
        label="create guest NFR stage",
    )
    lab.host(
        (_root("bin/mkdir"), "-p", f"{host_stage}/host"),
        label="create host NFR stage",
    )
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        edge_config = temporary / "edge.toml"
        nginx_config = temporary / "nginx.conf"
        edge_config.write_text(
            _edge_config(lab.root, lab.manifest, guest_stage),
            encoding="utf-8",
        )
        nginx_config.write_text(_nginx_config(lab.manifest), encoding="utf-8")
        lab.copy_to_guest(
            (str(bundle.path), str(edge_config), str(nginx_config)),
            str(guest_stage),
            label="copy guest NFR artifacts",
            recursive=True,
        )
    source_name = bundle.path.name
    if source_name != BUNDLE_DIRECTORY:
        lab.guest(
            (
                _root("bin/mv"),
                f"{guest_stage}/{source_name}",
                f"{guest_stage}/{BUNDLE_DIRECTORY}",
            ),
            label="normalize guest bundle stage",
        )
    lab.copy_to_host(
        (str(k6_binary), str(lab.root / "tests/load/proxy.js")),
        f"{host_stage}/host/",
        label="copy host k6 artifacts",
    )


def _install_nginx_origin(lab: RemoteLab, guest_stage: PurePosixPath) -> None:
    """Install one private high-port Nginx server and atomically reload."""

    manifest = lab.manifest
    absent = lab.guest(
        (
            _root("usr/bin/sudo"),
            "-n",
            _root("usr/bin/test"),
            "!",
            "-e",
            str(manifest.nginx_config),
        ),
        label="require NFR Nginx config absent",
        accepted_exit_codes=(0, 1),
    )
    if absent.exit_code != 0:
        fail(
            "VM_LOAD_NGINX_CONFIG_EXISTS",
            "NFR-001 전용 Nginx config가 이미 존재합니다.",
            str(manifest.nginx_config),
        )
    lab.guest(
        (
            _root("usr/bin/sudo"),
            "-n",
            _root("usr/bin/install"),
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            f"{guest_stage}/nginx.conf",
            str(manifest.nginx_config),
        ),
        label="install private Nginx origin",
    )
    _reload_nginx(lab, restored=False)


def _reload_nginx(lab: RemoteLab, *, restored: bool) -> None:
    suffix = "restored" if restored else "private origin"
    lab.guest(
        (
            _root("usr/bin/sudo"),
            "-n",
            _root("usr/sbin/nginx"),
            "-t",
        ),
        label=f"validate Nginx {suffix}",
    )
    lab.guest(
        (
            _root("usr/bin/sudo"),
            "-n",
            _root("usr/bin/systemctl"),
            "reload",
            lab.manifest.nginx_service,
        ),
        label=f"reload Nginx {suffix}",
    )


def _start_edge(
    lab: RemoteLab,
    guest_stage: PurePosixPath,
) -> tuple[RunningCommand, int]:
    """Run the release edge unprivileged through one owned SSH process."""

    pid_path = f"{guest_stage}/edge.pid"
    script = (
        f"echo $$ > {shlex.quote(pid_path)}; "
        f"exec env VPS_GUARD_CONFIG={shlex.quote(f'{guest_stage}/edge.toml')} "
        f"{shlex.quote(f'{guest_stage}/{BUNDLE_DIRECTORY}/bin/vps-guard-edge')}"
    )
    process = lab.start_guest(
        (_root("bin/sh"), "-c", script),
        label="start guest guard-edge",
    )
    try:
        pid_text = single_line(
            lab.guest(
                (_root("bin/cat"), pid_path),
                label="read guest edge PID",
            ).stdout,
            "edge PID",
        )
        if not pid_text.isdigit():
            fail(
                "VM_LOAD_EDGE_PID_INVALID",
                "guard-edge PID read-back이 올바르지 않습니다.",
                pid_text,
            )
        return process, int(pid_text)
    except HarnessError:
        process.stop(timeout_seconds=5)
        raise


def _wait_direct_and_guard(
    lab: RemoteLab,
    manifest: VmLoadRegressionManifest,
    *,
    direct_only: bool,
) -> None:
    lab.wait_http(
        f"http://{manifest.private_ip}:{manifest.direct_port}{manifest.request_path}",
        label="wait direct Nginx",
    )
    if direct_only:
        return
    lab.wait_http(
        f"http://{manifest.private_ip}:{manifest.edge_port}{manifest.request_path}",
        label="wait guard edge",
    )
    lab.wait_http(
        f"http://{manifest.private_ip}:{manifest.direct_port}/",
        label="smoke dynamic direct Nginx",
    )
    lab.wait_http(
        f"http://{manifest.private_ip}:{manifest.edge_port}/",
        label="smoke dynamic guard edge",
    )


def _run_k6(
    lab: RemoteLab,
    host_stage: PurePosixPath,
    evidence_dir: Path,
    number: int,
    kind: str,
) -> LoadMetrics:
    """Run one fixed off-guest load and parse the downloaded summary."""

    manifest = lab.manifest
    port = manifest.direct_port if kind == "direct" else manifest.edge_port
    remote_summary = f"{host_stage}/host/{kind}-{number}.json"
    lab.host(
        (
            _root("usr/bin/env"),
            f"TARGET_URL=http://{manifest.private_ip}:{port}{manifest.request_path}",
            f"TARGET_HOST={manifest.request_host}",
            f"VUS={manifest.vus}",
            f"DURATION={manifest.duration_seconds}s",
            f"THINK_TIME_SECONDS={manifest.think_time_ms / 1_000:g}",
            f"{host_stage}/host/k6",
            "run",
            "--summary-export",
            remote_summary,
            f"{host_stage}/host/proxy.js",
        ),
        label=f"k6 {kind} round {number}",
        timeout_seconds=manifest.duration_seconds + 45,
        accepted_exit_codes=(0, 99),
    )
    local_summary = evidence_dir / f"{kind}-{number}.json"
    lab.copy_from_host(
        remote_summary,
        local_summary,
        label=f"download {kind} round {number}",
    )
    return load_metrics(local_summary)


def _stop_remote_edge(lab: RemoteLab, edge_pid: int | None) -> bool:
    """Stop only the commit-staged Edge process, escalating after a bounded wait."""

    if edge_pid is None:
        return True
    try:
        actual = _edge_executable(lab, edge_pid)
        if actual is None:
            return True
        if (
            not actual.startswith(f"{lab.manifest.stage_base}/")
            or not actual.endswith(f"/{BUNDLE_DIRECTORY}/bin/vps-guard-edge")
        ):
            return False
        lab.guest(
            (_root("bin/kill"), "-TERM", str(edge_pid)),
            label="terminate guest edge",
            accepted_exit_codes=(0, 1),
        )
        if _wait_edge_exit(lab, edge_pid):
            return True
        if _edge_executable(lab, edge_pid) != actual:
            return False
        lab.guest(
            (_root("bin/kill"), "-KILL", str(edge_pid)),
            label="kill stuck guest edge",
            accepted_exit_codes=(0, 1),
        )
        return _wait_edge_exit(lab, edge_pid)
    except HarnessError:
        return False


def _edge_executable(lab: RemoteLab, edge_pid: int) -> str | None:
    result = lab.guest(
        (_root("bin/readlink"), "-f", f"/proc/{edge_pid}/exe"),
        label="read guest edge executable",
        accepted_exit_codes=(0, 1),
    )
    value = result.stdout.strip()
    return value if result.exit_code == 0 and value else None


def _wait_edge_exit(lab: RemoteLab, edge_pid: int) -> bool:
    for _attempt in range(25):
        result = lab.guest(
            (_root("bin/kill"), "-0", str(edge_pid)),
            label="wait guest edge exit",
            accepted_exit_codes=(0, 1),
        )
        if result.exit_code == 1:
            return True
        time.sleep(0.2)
    return False


def _restore_nginx(lab: RemoteLab, *, installed: bool) -> bool:
    if not installed:
        return True
    try:
        lab.guest(
            (
                _root("usr/bin/sudo"),
                "-n",
                _root("bin/rm"),
                "-f",
                "--",
                str(lab.manifest.nginx_config),
            ),
            label="remove private Nginx origin",
        )
        _reload_nginx(lab, restored=True)
        return True
    except HarnessError:
        return False


def _restore_memory(
    lab: RemoteLab,
    original_memory: int,
    *,
    changed: bool,
) -> bool:
    if not changed:
        return True
    try:
        lab.set_domain_memory(original_memory)
        lab.wait_guest_memory(original_memory)
        return lab.domain_memory() == original_memory
    except HarnessError:
        return False


def _remove_stages(
    lab: RemoteLab,
    guest_stage: PurePosixPath,
    host_stage: PurePosixPath,
    *,
    guest_created: bool,
    host_created: bool,
) -> bool:
    try:
        validate_stage(guest_stage)
        validate_stage(host_stage)
        if guest_created:
            lab.guest(
                (_root("bin/rm"), "-rf", "--", str(guest_stage)),
                label="remove guest NFR stage",
            )
        if host_created:
            lab.host(
                (_root("bin/rm"), "-rf", "--", str(host_stage)),
                label="remove host NFR stage",
            )
        return True
    except HarnessError:
        return False


def _require_stage_absent(
    lab: RemoteLab,
    stage: PurePosixPath,
    *,
    guest: bool,
) -> None:
    validate_stage(stage)
    command = (_root("usr/bin/test"), "!", "-e", str(stage))
    result = (
        lab.guest(
            command,
            label="require guest NFR stage absent",
            accepted_exit_codes=(0, 1),
        )
        if guest
        else lab.host(
            command,
            label="require host NFR stage absent",
            accepted_exit_codes=(0, 1),
        )
    )
    if result.exit_code != 0:
        fail("VM_LOAD_STAGE_EXISTS", "NFR-001 stage가 이미 존재합니다.", str(stage))


def _nginx_config(manifest: VmLoadRegressionManifest) -> str:
    return f"""server {{
    listen {manifest.private_ip}:{manifest.direct_port};
    server_name {manifest.request_host};
    root {manifest.site_root};
    index index.php index.html;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    location = /__vpsguard_nfr001 {{
        default_type text/html;
        return 200 '<!doctype html><title>VPSGuard NFR-001</title><main>normal browse fixture</main>';
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:{manifest.php_fpm_socket};
    }}

    location ~ /\\. {{
        deny all;
    }}
}}
"""


def _edge_config(
    root: Path,
    manifest: VmLoadRegressionManifest,
    guest_stage: PurePosixPath,
) -> str:
    source = (root / "configs/vps-guard.example.toml").read_text(encoding="utf-8")
    replacements = {
        'http_bind = "127.0.0.1:18080"': f'http_bind = "{manifest.private_ip}:{manifest.edge_port}"',
        "# worker_threads = 2": f"worker_threads = {manifest.worker_threads}",
        'allowed_hosts = ["example.com", "www.example.com"]': f'allowed_hosts = ["{manifest.request_host}"]',
        'canonical_host = "example.com"': f'canonical_host = "{manifest.request_host}"',
        'address = "127.0.0.1:18081"': f'address = "{manifest.private_ip}:{manifest.direct_port}"',
        'telemetry_socket = "/run/vps-guard/telemetry.sock"': f'telemetry_socket = "{guest_stage}/telemetry.sock"',
        'policy_path = "' + "/" + 'var/lib/vps-guard/policy.json"': f'policy_path = "{guest_stage}/policy.json"',
    }
    for old, new in replacements.items():
        if source.count(old) != 1:
            fail(
                "VM_LOAD_CONFIG_TEMPLATE_DRIFT",
                "edge config template 교체 지점이 정확하지 않습니다.",
                old,
            )
        source = source.replace(old, new)
    return source


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1_024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _root(relative: str) -> str:
    return "/" + relative
