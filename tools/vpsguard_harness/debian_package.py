"""Build a bounded Debian package from a verified VPSGuard release bundle."""

from __future__ import annotations

import argparse
import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError


@dataclass(frozen=True)
class PackageMetadata:
    """Validated Debian package identity."""

    version: str
    architecture: str


class DebianPackageError(HarnessError):
    """The release bundle cannot be represented as a safe Debian package."""


def build_package(bundle: Path, output: Path | None = None) -> Path:
    """Create a `.deb` without mutating the release bundle."""

    bundle = bundle.resolve(strict=True)
    metadata = _metadata(bundle)
    payload = _payload(bundle)
    destination = output or (
        bundle.parent.parent.parent
        / "debian"
        / f"vpsguard_{metadata.version}_{metadata.architecture}.deb"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    control = _control_archive(metadata)
    data = _tar_archive(payload)
    _write_ar(
        destination,
        (
            ("debian-binary", b"2.0\n", 0o100644),
            ("control.tar.gz", control, 0o100644),
            ("data.tar.gz", data, 0o100644),
        ),
    )
    return destination


def _metadata(bundle: Path) -> PackageMetadata:
    info = _required(bundle / "BUILD-INFO.txt").read_text(encoding="utf-8")
    values = dict(
        line.split("=", maxsplit=1)
        for line in info.splitlines()
        if "=" in line
    )
    target = values.get("target", "")
    architecture = {
        "x86_64-unknown-linux-gnu": "amd64",
        "aarch64-unknown-linux-gnu": "arm64",
    }.get(target)
    if architecture is None:
        raise _error(
            "DEBIAN_TARGET_UNSUPPORTED",
            f"target={target!r}",
            "지원하지 않는 CPU package가 생성될 수 있습니다.",
            "x86_64 또는 aarch64 Linux release bundle을 사용하십시오.",
        )
    prefix = "vpsguard-"
    version = bundle.name.removeprefix(prefix)
    if (
        not bundle.name.startswith(prefix)
        or not version
        or any(character not in "0123456789abcdefghijklmnopqrstuvwxyz.+~-" for character in version)
    ):
        raise _error(
            "DEBIAN_VERSION_INVALID",
            f"bundle={bundle.name}",
            "apt가 package version을 안정적으로 비교할 수 없습니다.",
            "vpsguard-<semver> release bundle 이름을 사용하십시오.",
        )
    return PackageMetadata(version=version, architecture=architecture)


def _payload(bundle: Path) -> list[tuple[Path, str, int]]:
    files: list[tuple[Path, str, int]] = []
    for binary in ("vps-guard", "vps-guard-control", "vps-guard-privileged", "vps-guard-edge"):
        files.append((_required(bundle / "bin" / binary), f"usr/local/bin/{binary}", 0o755))
    for source in sorted((bundle / "systemd").glob("*")):
        if source.is_file():
            files.append((source, f"etc/systemd/system/{source.name}", 0o644))
    dropin = _required(
        bundle
        / "systemd"
        / "vps-guard-control.service.d"
        / "20-cloudflare-credential.conf"
    )
    files.append(
        (
            dropin,
            "etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf",
            0o644,
        )
    )
    files.extend(
        [
            (
                _required(bundle / "tmpfiles" / "vps-guard.conf"),
                "usr/lib/tmpfiles.d/vps-guard.conf",
                0o644,
            ),
            (
                _required(bundle / "pam" / "vps-guard"),
                "etc/pam.d/vps-guard",
                0o644,
            ),
            (
                _required(bundle / "certbot" / "vps-guard-deploy-hook"),
                "usr/local/libexec/vps-guard/certbot-deploy-hook",
                0o755,
            ),
            (
                _required(bundle / "vps-guard.example.toml"),
                "usr/share/doc/vpsguard/examples/vps-guard.example.toml",
                0o640,
            ),
            (
                _required(bundle / "ownership-manifest.txt"),
                "usr/share/doc/vpsguard/ownership-manifest.txt",
                0o644,
            ),
        ]
    )
    return files


def _control_archive(metadata: PackageMetadata) -> bytes:
    control = (
        "Package: vpsguard\n"
        f"Version: {metadata.version}\n"
        "Section: net\n"
        "Priority: optional\n"
        f"Architecture: {metadata.architecture}\n"
        "Maintainer: VPSGuard maintainers\n"
        "Depends: ca-certificates, libc6, libgcc-s1, libpam0g, systemd\n"
        "Description: adaptive local traffic protection gateway\n"
        " Preserves the existing Nginx or Apache TLS ingress and application data.\n"
    ).encode()
    postinst = b"""#!/bin/sh
set -eu
getent group vps-guard >/dev/null || groupadd --system vps-guard
getent passwd vps-guard >/dev/null || useradd --system --gid vps-guard --home-dir /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard
getent group vpsguard-admin >/dev/null || groupadd --system vpsguard-admin
systemd-tmpfiles --create /usr/lib/tmpfiles.d/vps-guard.conf
install -d -m 0750 -o root -g vps-guard /etc/vps-guard/nginx /etc/vps-guard/apache
if [ ! -e /etc/vps-guard/config.toml ]; then
  install -m 0640 -o root -g vps-guard /usr/share/doc/vpsguard/examples/vps-guard.example.toml /etc/vps-guard/config.toml
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
printf '%s\n' 'VPSGuard installed without changing public ingress.'
printf '%s\n' 'Next: sudo vps-guard setup'
"""
    return _tar_bytes(
        (
            ("control", control, 0o644),
            ("postinst", postinst, 0o755),
        )
    )


def _tar_archive(payload: list[tuple[Path, str, int]]) -> bytes:
    entries = tuple((name, source.read_bytes(), mode) for source, name, mode in payload)
    return _tar_bytes(entries)


def _tar_bytes(entries: tuple[tuple[str, bytes, int], ...]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        for name, content, mode in entries:
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(content)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _write_ar(
    destination: Path,
    entries: tuple[tuple[str, bytes, int], ...],
) -> None:
    temporary = destination.with_suffix(f"{destination.suffix}.tmp-{os.getpid()}")
    try:
        with temporary.open("xb") as archive:
            archive.write(b"!<arch>\n")
            for name, content, mode in entries:
                encoded_name = f"{name}/"
                header = (
                    f"{encoded_name:<16}{0:<12}{0:<6}{0:<6}"
                    f"{mode:<8o}{len(content):<10}`\n"
                ).encode("ascii")
                if len(header) != 60:
                    raise _error(
                        "DEBIAN_AR_HEADER_INVALID",
                        f"name={name}",
                        "Debian archive가 손상될 수 있습니다.",
                        "package builder의 ar header 계약을 확인하십시오.",
                    )
                archive.write(header)
                archive.write(content)
                if len(content) % 2:
                    archive.write(b"\n")
            archive.flush()
            os.fsync(archive.fileno())
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def _required(path: Path) -> Path:
    if not path.is_file() or path.is_symlink():
        raise _error(
            "DEBIAN_BUNDLE_FILE_MISSING",
            f"path={path}",
            "불완전하거나 변조된 release bundle을 설치할 수 있습니다.",
            "checksum 검증을 통과한 release bundle을 다시 생성하십시오.",
        )
    return path


def _error(code: str, cause: str, impact: str, next_action: str) -> DebianPackageError:
    return DebianPackageError(
        code=code,
        problem="VPSGuard Debian package를 생성하지 못했습니다.",
        cause=cause,
        impact=impact,
        next_action=next_action,
    )


def main() -> int:
    """CLI entrypoint."""

    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    print(build_package(arguments.bundle, arguments.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
