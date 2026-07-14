#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-x86_64-unknown-linux-gnu}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
[[ -n "${version}" ]] || version="0.1.0"
bundle="${repo_root}/target/release-bundle/${target}/vpsguard-${version}"

cd "${repo_root}"
cargo build --locked --release --target "${target}" \
  -p guard-cli -p guard-control -p guard-edge

rm -rf "${bundle}"
mkdir -p "${bundle}/bin" "${bundle}/systemd" "${bundle}/tmpfiles"
install -m 0755 "target/${target}/release/vps-guard" "${bundle}/bin/"
install -m 0755 "target/${target}/release/vps-guard-control" "${bundle}/bin/"
install -m 0755 "target/${target}/release/vps-guard-edge" "${bundle}/bin/"
install -m 0644 packaging/systemd/*.service "${bundle}/systemd/"
install -m 0644 packaging/tmpfiles/vps-guard.conf "${bundle}/tmpfiles/"
install -m 0644 configs/vps-guard.example.toml "${bundle}/"

(cd "${bundle}" && shasum -a 256 bin/* > SHA256SUMS)
echo "release bundle: ${bundle}"
