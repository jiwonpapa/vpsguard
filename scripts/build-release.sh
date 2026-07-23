#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-x86_64-unknown-linux-gnu}"
build_tool="${CARGO_BUILD_TOOL:-cargo}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
[[ -n "${version}" ]] || version="0.1.0"
bundle="${repo_root}/target/release-bundle/${target}/vpsguard-${version}"
cd "${repo_root}"
trap 'bash scripts/build-storage.sh --auto || true' EXIT
export VPS_GUARD_BUILD_COMMIT="$(git rev-parse --verify HEAD)"
(cd web && bun ci && bun run check)
"${build_tool}" build --locked --release --target "${target}" \
  -p guard-cli -p guard-control -p guard-edge --bins
rm -rf "${bundle}"
mkdir -p "${bundle}/bin" \
  "${bundle}/systemd/vps-guard-control.service.d" \
  "${bundle}/systemd-examples" \
  "${bundle}/tmpfiles" "${bundle}/certbot" "${bundle}/pam" "${bundle}/scripts" "${bundle}/sbom" \
  "${bundle}/g7devops/nginx" "${bundle}/g7devops/systemd" \
  "${bundle}/g7devops/certbot" "${bundle}/gnuboard5/apache"
install -m 0755 target/${target}/release/vps-guard{,-control,-privileged,-edge} "${bundle}/bin/"
install -m 0644 packaging/systemd/*.service packaging/systemd/*.socket "${bundle}/systemd/"
install -m 0644 packaging/systemd/vps-guard-control-cloudflare-credential.conf \
  "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf"
install -m 0644 packaging/systemd/*.conf.example "${bundle}/systemd-examples/"
install -m 0644 packaging/tmpfiles/vps-guard.conf "${bundle}/tmpfiles/"
install -m 0644 packaging/ownership-manifest.txt "${bundle}/"
install -m 0755 packaging/certbot/vps-guard-deploy-hook "${bundle}/certbot/"
install -m 0644 packaging/pam/vps-guard "${bundle}/pam/"
install -m 0755 scripts/{deployment-state,state-common,operation-lock,g7devops-direct-state,restore-g7devops-direct,cutover-g7devops-direct,cutover-g7devops-remote,cutover-g7devops-direct-remote,ingress-transaction,update-release,uninstall}.sh "${bundle}/scripts/"
install -m 0755 tools/vm/{pam-login-probe,standalone-security-probe}.sh "${bundle}/scripts/"
install -m 0644 configs/vps-guard.example.toml "${bundle}/"
install -m 0644 configs/vps-guard.g7devops.shadow.toml "${bundle}/g7devops/vps-guard.shadow.toml"
install -m 0644 configs/vps-guard.g7devops.ingress.toml "${bundle}/g7devops/vps-guard.ingress.toml"
install -m 0644 configs/vps-guard.g7devops.direct.toml "${bundle}/g7devops/vps-guard.direct.toml"
install -m 0644 configs/nginx/g7devops-edge.conf "${bundle}/g7devops/nginx/edge.conf"
install -m 0644 configs/nginx/g7devops-bypass.conf "${bundle}/g7devops/nginx/bypass.conf"
install -m 0644 configs/nginx/g7devops-origin-only.conf "${bundle}/g7devops/nginx/origin-only.conf"
install -m 0644 configs/systemd/g7devops-edge-tls.conf "${bundle}/g7devops/systemd/edge-tls.conf"
install -m 0755 configs/certbot/g7devops-deploy-hook "${bundle}/g7devops/certbot/deploy-hook"
install -m 0644 configs/vps-guard.gnuboard5.observe.toml "${bundle}/gnuboard5/vps-guard.observe.toml"
install -m 0644 configs/vps-guard.gnuboard5.enforce.toml "${bundle}/gnuboard5/vps-guard.enforce.toml"
install -m 0644 configs/crawler-networks.json "${bundle}/gnuboard5/crawler-networks.json"
install -m 0644 configs/apache/{gnuboard5-guarded,gnuboard5-bypass,vpsguard-origin,vpsguard-origin-ports}.conf "${bundle}/gnuboard5/apache/"
install -m 0644 configs/apache/waf-*.conf configs/apache/gnuboard5-crs-exclusions.conf \
  "${bundle}/gnuboard5/apache/"
install -m 0644 docs/OPERATIONS.md "${bundle}/"
install -m 0644 docs/THIRD_PARTY_NOTICES.md "${bundle}/"
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
