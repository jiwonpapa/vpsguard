#!/usr/bin/env bash
set -euo pipefail

# EDGE-001, EDGE-002, TLS-005, OPS-003: 검증된 release bundle의 g7devops
# direct TLS 후보를 원격 트랜잭션에 전달합니다.
mode="${1:---plan}"
bundle="${2:-}"
target="${VPS_GUARD_SSH_TARGET:-g7devops}"

usage() {
  echo "usage: $0 --plan | --apply RELEASE_BUNDLE"
}

if [[ "${mode}" == "--plan" ]]; then
  echo "target: ssh ${target}"
  echo "topology: VPSGuard public 80/443 -> Nginx 127.0.0.1:18081 -> PHP-FPM"
  echo "certificate: existing Certbot lineage via systemd credentials"
  echo "rollback: persistent checksum snapshot of exact ingress/service state"
  echo "standalone restore: scripts/restore-g7devops-direct.sh"
  exit 0
fi
[[ "${mode}" == "--apply" && -d "${bundle}" ]] || { usage >&2; exit 2; }

for file in \
  BUILD-INFO.txt \
  SHA256SUMS \
  scripts/operation-lock.sh \
  scripts/g7devops-direct-state.sh \
  scripts/cutover-g7devops-direct-remote.sh \
  certbot/vps-guard-deploy-hook \
  g7devops/vps-guard.direct.toml \
  g7devops/certbot/deploy-hook \
  g7devops/nginx/origin-only.conf \
  g7devops/systemd/edge-tls.conf; do
  [[ -f "${bundle}/${file}" && ! -L "${bundle}/${file}" ]] || {
    echo "release file missing: ${file}" >&2
    exit 2
  }
done
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${bundle}" && sha256sum --check SHA256SUMS >/dev/null)
else
  (cd "${bundle}" && shasum -a 256 --check SHA256SUMS >/dev/null)
fi
commit="$(tail -1 "${bundle}/BUILD-INFO.txt")"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]]
[[ "${VPS_GUARD_DIRECT_CONFIRM:-}" == "g7devops:direct-tls:${commit}" ]] || {
  echo "VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls:${commit} is required" >&2
  exit 2
}

stage="$(ssh "${target}" 'mktemp -d /tmp/vpsguard-direct.XXXXXX')"
cleanup() {
  # shellcheck disable=SC2029 # validated mktemp path intentionally expands locally
  ssh "${target}" "rm -rf -- '${stage}'" >/dev/null 2>&1 || true
}
trap cleanup EXIT
scp -q "${bundle}/g7devops/vps-guard.direct.toml" "${target}:${stage}/direct.toml"
scp -q "${bundle}/g7devops/nginx/origin-only.conf" "${target}:${stage}/origin-only.conf"
scp -q "${bundle}/g7devops/systemd/edge-tls.conf" "${target}:${stage}/edge-tls.conf"
scp -q "${bundle}/certbot/vps-guard-deploy-hook" \
  "${target}:${stage}/certbot-deploy-hook"
scp -q "${bundle}/g7devops/certbot/deploy-hook" \
  "${target}:${stage}/g7-certbot-deploy-hook"
scp -q "${bundle}/scripts/cutover-g7devops-direct-remote.sh" \
  "${target}:${stage}/cutover-direct.sh"
scp -q "${bundle}/scripts/operation-lock.sh" \
  "${target}:${stage}/operation-lock.sh"
scp -q "${bundle}/scripts/g7devops-direct-state.sh" \
  "${target}:${stage}/direct-state.sh"
# shellcheck disable=SC2029 # validated mktemp path intentionally expands locally
ssh "${target}" \
  "sudo VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls bash '${stage}/cutover-direct.sh' '${stage}'"
