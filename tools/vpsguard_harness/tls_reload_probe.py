"""Body-free TLS availability, certificate and persistent-connection probes."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
from pathlib import Path

from .release_endurance_model import ProbeAvailability, ProbeSample
from .runner import CommandRunner, CommandScope, CommandSpec
from .tls_reload_model import TlsReloadManifest, fail


class TlsProbeTimeline:
    """Record exact TLS status every 100ms without retaining response bodies."""

    def __init__(
        self,
        root: Path,
        manifest: TlsReloadManifest,
        ca_bundle: Path,
        evidence: Path,
        *,
        connect_ip: str,
    ) -> None:
        self.root = root
        self.manifest = manifest
        self.ca_bundle = ca_bundle
        self.evidence = evidence
        self.connect_ip = connect_ip
        self.availability = ProbeAvailability(expected_status=200)
        self.max_schedule_lag_ms = 0
        self._condition = threading.Condition()
        self._consecutive_successes = 0
        self._error: Exception | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="vpsguard-tls-reload-probe",
            daemon=True,
        )
        self._started_ns = 0

    @property
    def samples(self) -> int:
        """Return the completed sample count."""

        with self._condition:
            return self.availability.samples

    def start(self) -> None:
        """Start the bounded probe thread."""

        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        self._started_ns = time.monotonic_ns()
        self._thread.start()

    def wait_healthy(self, *, after_samples: int, timeout_seconds: int = 10) -> bool:
        """Require five new consecutive exact 200 responses."""

        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while time.monotonic() < deadline:
                if self._error is not None:
                    raise self._error
                if (
                    self.availability.samples >= after_samples + 5
                    and self._consecutive_successes >= 5
                ):
                    return True
                self._condition.wait(timeout=min(0.2, deadline - time.monotonic()))
        return False

    def stop(self) -> dict[str, object]:
        """Stop and return one stable availability summary."""

        self._stop.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            fail("TLS_RELOAD_PROBE_STOP_TIMEOUT", "TLS probe thread가 종료되지 않았습니다.", "join=5s")
        if self._error is not None:
            raise self._error
        completed_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
        return {
            **self.availability.finish(completed_ms),
            "interval_ms": self.manifest.interval_ms,
            "expected_status": 200,
            "max_schedule_lag_ms": self.max_schedule_lag_ms,
        }

    def _run(self) -> None:
        runner = CommandRunner()
        sequence = 0
        try:
            with self.evidence.open("w", encoding="utf-8") as stream:
                while not self._stop.is_set():
                    scheduled_ms = sequence * self.manifest.interval_ms
                    scheduled_ns = self._started_ns + scheduled_ms * 1_000_000
                    remaining = (scheduled_ns - time.monotonic_ns()) / 1_000_000_000
                    if remaining > 0 and self._stop.wait(remaining):
                        break
                    started_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
                    result = runner.run(
                        CommandSpec(
                            label=f"TLS reload probe {sequence}",
                            argv=self.command(),
                            cwd=self.root,
                            timeout_seconds=3,
                            scope=CommandScope.TEST,
                            accepted_exit_codes=tuple(range(-64, 256)),
                            max_output_bytes=4_096,
                        )
                    )
                    completed_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
                    status = _probe_status(result.stdout)
                    stream.write(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "sequence": sequence,
                                "scheduled_ms": scheduled_ms,
                                "started_ms": started_ms,
                                "elapsed_ms": result.elapsed_ms,
                                "http_status": status,
                                "curl_exit": result.exit_code,
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    stream.flush()
                    with self._condition:
                        self.availability.observe(
                            ProbeSample(
                                started_ms=started_ms,
                                completed_ms=completed_ms,
                                status=status,
                                exit_code=result.exit_code,
                            )
                        )
                        self.max_schedule_lag_ms = max(
                            self.max_schedule_lag_ms,
                            max(0, started_ms - scheduled_ms),
                        )
                        if result.exit_code == 0 and status == 200:
                            self._consecutive_successes += 1
                        else:
                            self._consecutive_successes = 0
                        self._condition.notify_all()
                    sequence += 1
        except Exception as error:  # pragma: no cover - propagated to owner
            with self._condition:
                self._error = error
                self._condition.notify_all()

    def command(self) -> tuple[str, ...]:
        """Return the exact body-free curl command."""

        return (
            "curl",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}\t%{time_total}\\n",
            "--connect-timeout",
            "1",
            "--max-time",
            "2",
            "--resolve",
            f"{self.manifest.probe_host}:{self.manifest.probe_port}:{self.connect_ip}",
            "--cacert",
            str(self.ca_bundle),
            self.manifest.probe_url,
        )


class PersistentTlsConnection:
    """One TLS socket that never reconnects while the old worker drains."""

    def __init__(
        self,
        manifest: TlsReloadManifest,
        ca_bundle: Path,
        *,
        connect_ip: str,
    ) -> None:
        context = ssl.create_default_context(cafile=str(ca_bundle))
        raw = socket.create_connection(
            (connect_ip, manifest.probe_port),
            timeout=3,
        )
        self._socket = context.wrap_socket(raw, server_hostname=manifest.probe_host)
        self._socket.settimeout(3)
        self._host = manifest.probe_host
        self._inflight_started = False
        self.fileno = self._socket.fileno()
        certificate = self._socket.getpeercert(binary_form=True)
        if not certificate:
            fail("TLS_RELOAD_PEER_CERT_MISSING", "기존 TLS 연결 인증서를 받지 못했습니다.", "empty DER")
        self.certificate_sha256 = hashlib.sha256(certificate).hexdigest()

    @property
    def is_same_open_socket(self) -> bool:
        """Return whether the original TLS socket remains open without reconnecting."""

        return self.fileno >= 0 and self.fileno == self._socket.fileno()

    def start_inflight_request(self) -> None:
        """Start one synthetic POST and leave its bounded body incomplete."""

        if self._inflight_started:
            fail(
                "TLS_RELOAD_INFLIGHT_DUPLICATE",
                "TLS drain 검증 요청이 이미 시작됐습니다.",
                "duplicate start",
            )
        initial, _finish = inflight_request_chunks(self._host)
        self._socket.sendall(initial)
        self._inflight_started = True

    def finish_inflight_request(self) -> int:
        """Complete the synthetic request on the original TLS socket."""

        if not self._inflight_started:
            fail(
                "TLS_RELOAD_INFLIGHT_NOT_STARTED",
                "TLS drain 검증 요청이 시작되지 않았습니다.",
                "finish before start",
            )
        _initial, finish = inflight_request_chunks(self._host)
        self._socket.sendall(finish)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) <= 16_384:
            chunk = self._socket.recv(4_096)
            if not chunk:
                fail("TLS_RELOAD_KEEPALIVE_CLOSED", "기존 TLS 연결이 drain 중 닫혔습니다.", "EOF")
            response.extend(chunk)
        if b"\r\n\r\n" not in response:
            fail("TLS_RELOAD_HEADER_TOO_LARGE", "기존 TLS 응답 header가 상한을 넘었습니다.", str(len(response)))
        status_line = bytes(response).split(b"\r\n", maxsplit=1)[0].split()
        if len(status_line) < 2 or not status_line[1].isdigit():
            fail("TLS_RELOAD_STATUS_INVALID", "기존 TLS 응답 status를 해석하지 못했습니다.", repr(status_line))
        return int(status_line[1])

    def close(self) -> None:
        """Close the persistent TLS socket."""

        self._socket.close()


def certificate_fingerprint(path: Path) -> str:
    """Return SHA-256 of the first PEM certificate DER."""

    pem = path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


def inflight_request_chunks(host: str) -> tuple[bytes, bytes]:
    """Return one bounded synthetic POST split inside its 32-byte body."""

    headers = (
        "POST /__vpsguard_tls_drain_probe__ HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 32\r\n"
        "Connection: close\r\n"
        "User-Agent: vpsguard-tls-drain-proof\r\n\r\n"
    ).encode("ascii")
    return headers + b"x", b"x" * 31


def served_fingerprint(
    manifest: TlsReloadManifest,
    ca_bundle: Path,
    *,
    connect_ip: str,
) -> str:
    """Read one newly established listener certificate SHA-256."""

    context = ssl.create_default_context(cafile=str(ca_bundle))
    with socket.create_connection((connect_ip, manifest.probe_port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=manifest.probe_host) as tls:
            certificate = tls.getpeercert(binary_form=True)
    if not certificate:
        fail("TLS_RELOAD_PEER_CERT_MISSING", "새 TLS 연결 인증서를 받지 못했습니다.", "empty DER")
    return hashlib.sha256(certificate).hexdigest()


def wait_for_fingerprint(
    manifest: TlsReloadManifest,
    ca_bundle: Path,
    expected_sha256: str,
    *,
    connect_ip: str,
    timeout_seconds: int = 15,
) -> str:
    """Wait until new connections consistently serve the renewed leaf."""

    deadline = time.monotonic() + timeout_seconds
    consecutive = 0
    observed = ""
    while time.monotonic() < deadline:
        try:
            observed = served_fingerprint(
                manifest,
                ca_bundle,
                connect_ip=connect_ip,
            )
        except (OSError, ssl.SSLError):
            consecutive = 0
        else:
            consecutive = consecutive + 1 if observed == expected_sha256 else 0
            if consecutive >= 5:
                return observed
        time.sleep(0.2)
    fail(
        "TLS_RELOAD_FINGERPRINT_TIMEOUT",
        "새 연결에서 갱신 인증서를 연속 확인하지 못했습니다.",
        f"expected={expected_sha256}, observed={observed}",
    )


def _probe_status(output: str) -> int:
    field = output.strip().split("\t", maxsplit=1)[0]
    return int(field) if field.isdigit() else 0
