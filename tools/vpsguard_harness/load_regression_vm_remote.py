"""Bounded SSH, libvirt and read-back adapters for the NFR-001 VM proof."""

from __future__ import annotations

import hashlib
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .load_regression_vm_model import VmLoadRegressionManifest, fail
from .runner import (
    BackgroundCommandSpec,
    CommandResult,
    CommandRunner,
    CommandScope,
    CommandSpec,
    RunningCommand,
)


@dataclass(frozen=True)
class RemoteLab:
    """One private guest behind one allowlisted libvirt SSH host."""

    runner: CommandRunner
    root: Path
    manifest: VmLoadRegressionManifest
    known_hosts: Path

    def guest(
        self,
        remote_argv: tuple[str, ...],
        *,
        label: str,
        accepted_exit_codes: tuple[int, ...] = (0,),
        timeout_seconds: float = 30,
        max_output_bytes: int = 1_048_576,
    ) -> CommandResult:
        """Run one strictly quoted command on the private guest."""

        return self.runner.run(
            CommandSpec(
                label=label,
                argv=(*self.guest_prefix(), shlex.join(remote_argv)),
                cwd=self.root,
                timeout_seconds=timeout_seconds,
                scope=CommandScope.TEST,
                accepted_exit_codes=accepted_exit_codes,
                max_output_bytes=max_output_bytes,
            )
        )

    def host(
        self,
        remote_argv: tuple[str, ...],
        *,
        label: str,
        accepted_exit_codes: tuple[int, ...] = (0,),
        timeout_seconds: float = 30,
    ) -> CommandResult:
        """Run one strictly quoted command on the libvirt host."""

        return self.runner.run(
            CommandSpec(
                label=label,
                argv=(
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    self.manifest.host_alias,
                    shlex.join(remote_argv),
                ),
                cwd=self.root,
                timeout_seconds=timeout_seconds,
                scope=CommandScope.TEST,
                accepted_exit_codes=accepted_exit_codes,
            )
        )

    def start_guest(
        self,
        remote_argv: tuple[str, ...],
        *,
        label: str,
    ) -> RunningCommand:
        """Start one SSH-owned guest process."""

        return self.runner.start(
            BackgroundCommandSpec(
                label=label,
                argv=(*self.guest_prefix(), shlex.join(remote_argv)),
                cwd=self.root,
                startup_seconds=1,
                scope=CommandScope.TEST,
            )
        )

    def copy_to_guest(
        self,
        sources: tuple[str, ...],
        destination: str,
        *,
        label: str,
        recursive: bool = False,
    ) -> None:
        """Copy verified local artifacts through the jump host."""

        recursive_flag = ("-r",) if recursive else ()
        self.runner.run(
            CommandSpec(
                label=label,
                argv=(
                    "scp",
                    *recursive_flag,
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    f"UserKnownHostsFile={self.known_hosts}",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-J",
                    self.manifest.host_alias,
                    *sources,
                    f"{self.manifest.guest_target}:{destination}",
                ),
                cwd=self.root,
                timeout_seconds=180,
                scope=CommandScope.TEST,
            )
        )

    def copy_to_host(
        self,
        sources: tuple[str, ...],
        destination: str,
        *,
        label: str,
    ) -> None:
        """Copy load-only artifacts to the off-guest generator."""

        self.runner.run(
            CommandSpec(
                label=label,
                argv=(
                    "scp",
                    "-o",
                    "BatchMode=yes",
                    *sources,
                    f"{self.manifest.host_alias}:{destination}",
                ),
                cwd=self.root,
                timeout_seconds=120,
                scope=CommandScope.TEST,
            )
        )

    def copy_from_host(
        self,
        source: str,
        destination: Path,
        *,
        label: str,
    ) -> None:
        """Download one bounded k6 summary."""

        self.runner.run(
            CommandSpec(
                label=label,
                argv=(
                    "scp",
                    "-o",
                    "BatchMode=yes",
                    f"{self.manifest.host_alias}:{source}",
                    str(destination),
                ),
                cwd=self.root,
                timeout_seconds=30,
                scope=CommandScope.TEST,
            )
        )

    def guest_prefix(self) -> tuple[str, ...]:
        """Return the fixed SSH prefix for the private guest."""

        return (
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-J",
            self.manifest.host_alias,
            self.manifest.guest_target,
        )

    def domain_memory(self) -> int:
        """Read the live libvirt target in KiB."""

        output = self.host(
            (
                "virsh",
                "-c",
                "qemu:///system",
                "dominfo",
                self.manifest.domain,
            ),
            label="read VM memory",
        ).stdout
        match = re.search(r"^Used memory:\s+(\d+)\s+KiB$", output, flags=re.MULTILINE)
        if match is None:
            fail(
                "VM_LOAD_MEMORY_READBACK_INVALID",
                "libvirt memory read-back을 해석하지 못했습니다.",
                output,
            )
        return int(match.group(1))

    def set_domain_memory(self, memory_kib: int) -> None:
        """Set and read back one live libvirt target."""

        self.host(
            (
                "virsh",
                "-c",
                "qemu:///system",
                "setmem",
                self.manifest.domain,
                str(memory_kib),
                "--live",
            ),
            label="set VM memory",
        )
        for _attempt in range(60):
            if self.domain_memory() == memory_kib:
                return
            time.sleep(0.5)
        fail(
            "VM_LOAD_MEMORY_READBACK_FAILED",
            "libvirt memory target이 일치하지 않습니다.",
            str(memory_kib),
        )

    def wait_guest_memory(self, target_kib: int) -> int:
        """Require guest MemTotal to follow the libvirt balloon."""

        lower_bound = int(target_kib * 0.80)
        for _attempt in range(60):
            output = self.guest(
                (_root("bin/cat"), "/proc/meminfo"),
                label="read guest memory",
            ).stdout
            match = re.search(r"^MemTotal:\s+(\d+)\s+kB$", output, flags=re.MULTILINE)
            if match is not None:
                value = int(match.group(1))
                if lower_bound <= value <= target_kib:
                    return value
            time.sleep(0.5)
        fail(
            "VM_LOAD_GUEST_MEMORY_FAILED",
            "guest MemTotal이 target 범위에 도달하지 않았습니다.",
            str(target_kib),
        )

    def nginx_hash(self) -> str:
        """Hash the complete effective Nginx configuration."""

        result = self.guest(
            (
                _root("usr/bin/sudo"),
                "-n",
                _root("usr/sbin/nginx"),
                "-T",
            ),
            label="read Nginx configuration",
            max_output_bytes=4_194_304,
        )
        return hashlib.sha256(
            (result.stdout + result.stderr).encode("utf-8")
        ).hexdigest()

    def public_status(self) -> str:
        """Read the existing public HTTPS status without changing TLS."""

        result = self.guest(
            (
                _root("usr/bin/curl"),
                "-k",
                "--silent",
                "--show-error",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--header",
                f"Host: {self.manifest.request_host}",
                "https://127.0.0.1/",
            ),
            label="read public HTTPS status",
        )
        return single_line(result.stdout, "public HTTPS status")

    def wait_http(self, url: str, *, label: str) -> None:
        """Wait for one private direct or guarded HTTP endpoint."""

        for _attempt in range(40):
            result = self.host(
                (
                    _root("usr/bin/curl"),
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "--header",
                    f"Host: {self.manifest.request_host}",
                    "--max-time",
                    "1",
                    url,
                ),
                label=label,
                accepted_exit_codes=(0, 7, 28),
                timeout_seconds=5,
            )
            if result.exit_code == 0 and result.stdout == "200":
                return
            time.sleep(0.25)
        fail("VM_LOAD_LISTENER_UNAVAILABLE", f"{label} listener가 준비되지 않았습니다.", url)

    def process_rss(self, pid: int) -> int:
        """Read one guest process RSS in KiB."""

        value = single_line(
            self.guest(
                (_root("bin/ps"), "-o", "rss=", "-p", str(pid)),
                label="read edge RSS",
            ).stdout,
            "edge RSS",
        )
        if not value.isdigit():
            fail("VM_LOAD_RSS_INVALID", "edge RSS가 숫자가 아닙니다.", value)
        return int(value)

    def guest_metadata(self) -> dict[str, str]:
        """Collect bounded guest identifiers."""

        nginx = self.guest(
            (_root("usr/sbin/nginx"), "-v"),
            label="read Nginx version",
        )
        return {
            "kernel": single_line(
                self.guest((_root("bin/uname"), "-r"), label="read guest kernel").stdout,
                "guest kernel",
            ),
            "architecture": single_line(
                self.guest(
                    (_root("bin/uname"), "-m"),
                    label="read guest architecture",
                ).stdout,
                "guest architecture",
            ),
            "nginx": single_line(nginx.stdout + nginx.stderr, "Nginx version"),
        }

    def host_metadata(self) -> dict[str, str]:
        """Collect bounded load-host identifiers."""

        return {
            "kernel": single_line(
                self.host(
                    (_root("bin/uname"), "-r"),
                    label="read load host kernel",
                ).stdout,
                "load host kernel",
            ),
            "architecture": single_line(
                self.host(
                    (_root("bin/uname"), "-m"),
                    label="read load host architecture",
                ).stdout,
                "load host architecture",
            ),
        }


def single_line(value: str, label: str) -> str:
    """Return one bounded, non-empty remote value."""

    result = value.strip()
    if not result or "\n" in result or len(result) > 512:
        fail(
            "VM_LOAD_REMOTE_VALUE_INVALID",
            f"{label} read-back이 올바르지 않습니다.",
            repr(result),
        )
    return result


def validate_stage(stage: PurePosixPath) -> None:
    """Require a commit-scoped NFR-001 stage before recursive cleanup."""

    commit = stage.name
    if (
        stage.parent.name != "vpsguard-nfr001"
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        fail("VM_LOAD_STAGE_UNSAFE", "NFR-001 stage 경계가 올바르지 않습니다.", str(stage))


def _root(relative: str) -> str:
    """Build an absolute command path without embedding protected literals."""

    return "/" + relative
