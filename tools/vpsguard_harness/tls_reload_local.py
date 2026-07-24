"""Local certificate fixture and owned SSH tunnel resources for TLS reload proof."""

from __future__ import annotations

import socket
import time
from pathlib import Path

from .runner import (
    BackgroundCommandSpec,
    CommandRunner,
    CommandScope,
    CommandSpec,
    RunningCommand,
)
from .tls_reload_model import TlsReloadManifest, fail

TUNNEL_IP = "127.0.0.1"


def generate_certificates(
    runner: CommandRunner,
    root: Path,
    fixture: Path,
    hostname: str,
) -> None:
    """Generate two ephemeral exact-SAN certificates and one local CA bundle."""

    for name in ("initial", "renewed"):
        runner.run(
            CommandSpec(
                label=f"generate {name} TLS reload fixture",
                argv=(
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    f"/CN={hostname}",
                    "-addext",
                    f"subjectAltName=DNS:{hostname}",
                    "-keyout",
                    str(fixture / f"{name}-key.pem"),
                    "-out",
                    str(fixture / f"{name}-cert.pem"),
                ),
                cwd=root,
                timeout_seconds=20,
                scope=CommandScope.TEST,
                max_output_bytes=16_384,
            )
        )
    (fixture / "ca-bundle.pem").write_text(
        (fixture / "initial-cert.pem").read_text(encoding="ascii")
        + (fixture / "renewed-cert.pem").read_text(encoding="ascii"),
        encoding="ascii",
    )


def open_tunnel(
    runner: CommandRunner,
    root: Path,
    manifest: TlsReloadManifest,
) -> RunningCommand:
    """Open one owned SSH local forward without changing the guest firewall."""

    _require_local_port_available(manifest.probe_port)
    tunnel = runner.start(
        BackgroundCommandSpec(
            label="open isolated TLS reload SSH tunnel",
            argv=(
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-N",
                "-L",
                f"{TUNNEL_IP}:{manifest.probe_port}:"
                f"{TUNNEL_IP}:{manifest.probe_port}",
                manifest.protection.guest_copy_target,
            ),
            cwd=root,
            startup_seconds=1,
            scope=CommandScope.TEST,
            max_output_bytes=16_384,
        )
    )
    try:
        _wait_local_port(manifest.probe_port, expected_available=False)
    except Exception:
        tunnel.stop()
        raise
    return tunnel


def close_tunnel(tunnel: RunningCommand, port: int) -> None:
    """Terminate, reap and verify removal of one owned SSH forward."""

    tunnel.stop()
    _wait_local_port(port, expected_available=True)


def _require_local_port_available(port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((TUNNEL_IP, port))
    except OSError as error:
        fail(
            "TLS_RELOAD_TUNNEL_PORT_BUSY",
            "TLS reload SSH tunnel local port를 사용할 수 없습니다.",
            str(error),
        )


def _wait_local_port(port: int, *, expected_available: bool) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind((TUNNEL_IP, port))
        except OSError:
            available = False
        else:
            available = True
        if available == expected_available:
            return
        time.sleep(0.05)
    fail(
        "TLS_RELOAD_TUNNEL_STATE_TIMEOUT",
        "TLS reload SSH tunnel listener 상태가 제한 시간 안에 바뀌지 않았습니다.",
        f"port={port}, expected_available={expected_available}",
    )
