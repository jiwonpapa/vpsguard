#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-x86_64-unknown-linux-gnu}"
build_tool="${CARGO_BUILD_TOOL:-cargo}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
[[ -n "${version}" ]] || version="0.1.0"
bundle="${repo_root}/target/release-bundle/${target}/vpsguard-${version}"

cd "${repo_root}"
(cd web && bun ci && bun run check)
"${build_tool}" build --locked --release --target "${target}" \
  -p guard-cli -p guard-control -p guard-edge

rm -rf "${bundle}"
mkdir -p "${bundle}/bin" \
  "${bundle}/systemd/vps-guard-control.service.d" \
  "${bundle}/systemd-examples" \
  "${bundle}/tmpfiles" "${bundle}/certbot" "${bundle}/scripts" "${bundle}/sbom" \
  "${bundle}/g7devops/nginx" "${bundle}/g7devops/systemd" \
  "${bundle}/g7devops/certbot"
install -m 0755 "target/${target}/release/vps-guard" "${bundle}/bin/"
install -m 0755 "target/${target}/release/vps-guard-control" "${bundle}/bin/"
install -m 0755 "target/${target}/release/vps-guard-edge" "${bundle}/bin/"
install -m 0644 packaging/systemd/*.service "${bundle}/systemd/"
install -m 0644 \
  packaging/systemd/vps-guard-control-cloudflare-credential.conf \
  "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf"
install -m 0644 packaging/systemd/*.conf.example "${bundle}/systemd-examples/"
install -m 0644 packaging/tmpfiles/vps-guard.conf "${bundle}/tmpfiles/"
install -m 0644 packaging/ownership-manifest.txt "${bundle}/"
install -m 0755 packaging/certbot/vps-guard-deploy-hook "${bundle}/certbot/"
install -m 0755 \
  scripts/deployment-state.sh \
  scripts/cutover-g7devops-direct.sh \
  scripts/cutover-g7devops-remote.sh \
  scripts/cutover-g7devops-direct-remote.sh \
  scripts/ingress-transaction.sh \
  scripts/update-release.sh \
  scripts/uninstall.sh \
  "${bundle}/scripts/"
install -m 0644 configs/vps-guard.example.toml "${bundle}/"
install -m 0644 configs/vps-guard.g7devops.shadow.toml \
  "${bundle}/g7devops/vps-guard.shadow.toml"
install -m 0644 configs/vps-guard.g7devops.ingress.toml \
  "${bundle}/g7devops/vps-guard.ingress.toml"
install -m 0644 configs/vps-guard.g7devops.direct.toml \
  "${bundle}/g7devops/vps-guard.direct.toml"
install -m 0644 configs/nginx/g7devops-edge.conf \
  "${bundle}/g7devops/nginx/edge.conf"
install -m 0644 configs/nginx/g7devops-bypass.conf \
  "${bundle}/g7devops/nginx/bypass.conf"
install -m 0644 configs/nginx/g7devops-origin-only.conf \
  "${bundle}/g7devops/nginx/origin-only.conf"
install -m 0644 configs/systemd/g7devops-edge-tls.conf \
  "${bundle}/g7devops/systemd/edge-tls.conf"
install -m 0755 configs/certbot/g7devops-deploy-hook \
  "${bundle}/g7devops/certbot/deploy-hook"
install -m 0644 docs/OPERATIONS.md "${bundle}/"

if command -v cargo-cyclonedx >/dev/null 2>&1; then
  for package in guard-cli guard-control guard-edge; do
    cargo cyclonedx \
      --manifest-path "crates/${package}/Cargo.toml" \
      --format json --describe binaries --all-features \
      --target "${target}" --target-in-filename
    find "crates/${package}" -maxdepth 1 -name '*.cdx.json' \
      -exec install -m 0644 {} "${bundle}/sbom/${package}-${target}.cdx.json" \;
  done
else
  if [[ "${REQUIRE_CYCLONEDX:-0}" == "1" ]]; then
    echo "cargo-cyclonedx is required for release artifacts" >&2
    exit 2
  fi
  cargo metadata --locked --format-version 1 >"${bundle}/sbom/cargo-metadata.json"
fi
{
  echo "target=${target}"
  echo "version=${version}"
  rustc -Vv
  git rev-parse HEAD
} >"${bundle}/BUILD-INFO.txt"

checksums="${bundle}.SHA256SUMS.tmp"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${bundle}" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"${checksums}"
else
  (cd "${bundle}" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) >"${checksums}"
fi
install -m 0644 "${checksums}" "${bundle}/SHA256SUMS"
rm -f "${checksums}"
echo "release bundle: ${bundle}"
