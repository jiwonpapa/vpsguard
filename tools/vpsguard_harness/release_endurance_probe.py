"""Continuous body-free public probe used by the release endurance harness."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .release_endurance_model import (
    ProbeAvailability,
    ProbeSample,
    ReleaseEnduranceManifest,
    fail,
    public_probe_command,
)
from .runner import CommandRunner, CommandScope, CommandSpec


class EndurancePhase:
    """Thread-safe cycle and phase label for public probe evidence."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cycle = 0
        self._phase = "preflight"

    def set(self, cycle: int, phase: str) -> None:
        """Publish one bounded operation phase."""

        with self._lock:
            self._cycle = cycle
            self._phase = phase

    def get(self) -> tuple[int, str]:
        """Read one internally generated cycle and phase."""

        with self._lock:
            return self._cycle, self._phase


class ProbeTimeline:
    """Record exact public status continuously while VM updates execute."""

    def __init__(
        self,
        root: Path,
        manifest: ReleaseEnduranceManifest,
        evidence: Path,
        phase: EndurancePhase,
    ) -> None:
        self.root = root
        self.manifest = manifest
        self.evidence = evidence
        self.phase = phase
        self.availability = ProbeAvailability(expected_status=manifest.expected_status)
        self.max_schedule_lag_ms = 0
        self._condition = threading.Condition()
        self._consecutive_successes = 0
        self._error: Exception | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="vpsguard-public-probe",
            daemon=True,
        )
        self._started_ns = 0

    @property
    def samples(self) -> int:
        """Return the completed public probe sample count."""

        with self._condition:
            return self.availability.samples

    def start(self) -> None:
        """Start one bounded probe thread."""

        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        self._started_ns = time.monotonic_ns()
        self._thread.start()

    def wait_healthy(self, *, after_samples: int, timeout_seconds: int = 10) -> bool:
        """Require three new consecutive exact-status samples."""

        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while time.monotonic() < deadline:
                if self._error is not None:
                    raise self._error
                if (
                    self.availability.samples >= after_samples + 3
                    and self._consecutive_successes >= 3
                ):
                    return True
                self._condition.wait(timeout=min(0.2, deadline - time.monotonic()))
        return False

    def current_max_outage_ms(self) -> int:
        """Return the current real-time consecutive outage duration."""

        with self._condition:
            completed_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
            return int(self.availability.finish(completed_ms)["max_outage_ms"])

    def stop(self) -> dict[str, object]:
        """Stop the probe and return its stable evidence summary."""

        self._stop.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            fail(
                "ENDURANCE_PROBE_STOP_TIMEOUT",
                "public probe thread가 종료되지 않았습니다.",
                "join timeout=5s",
            )
        if self._error is not None:
            raise self._error
        completed_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
        return {
            **self.availability.finish(completed_ms),
            "interval_ms": self.manifest.interval_ms,
            "expected_status": self.manifest.expected_status,
            "max_schedule_lag_ms": self.max_schedule_lag_ms,
        }

    def _run(self) -> None:
        command = public_probe_command(self.manifest)
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
                            label=f"endurance public probe {sequence}",
                            argv=command,
                            cwd=self.root,
                            timeout_seconds=3,
                            scope=CommandScope.TEST,
                            accepted_exit_codes=tuple(range(-64, 256)),
                            max_output_bytes=4_096,
                        )
                    )
                    completed_ms = (time.monotonic_ns() - self._started_ns) // 1_000_000
                    status = _probe_status(result.stdout)
                    cycle, phase = self.phase.get()
                    record = {
                        "schema_version": 1,
                        "sequence": sequence,
                        "cycle": cycle,
                        "phase": phase,
                        "scheduled_ms": scheduled_ms,
                        "started_ms": started_ms,
                        "elapsed_ms": result.elapsed_ms,
                        "http_status": status,
                        "curl_exit": result.exit_code,
                    }
                    stream.write(
                        json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
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
                        if result.exit_code == 0 and status == self.manifest.expected_status:
                            self._consecutive_successes += 1
                        else:
                            self._consecutive_successes = 0
                        self._condition.notify_all()
                    sequence += 1
        except Exception as error:  # pragma: no cover - propagated to the owner thread
            with self._condition:
                self._error = error
                self._condition.notify_all()


def _probe_status(output: str) -> int:
    field = output.strip().split("\t", maxsplit=1)[0]
    return int(field) if field.isdigit() else 0
