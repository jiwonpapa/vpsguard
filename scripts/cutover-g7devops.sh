#!/usr/bin/env bash
# shellcheck disable=SC2029 # fixed target and regex-validated values are intentionally expanded for SSH
set -euo pipefail

# OPS-002, OPS-003, OPS-004, TLS-005, ACT-010: 검증된 release와 고정된
# g7devops 후보만 staging하고 원격 transaction에 commit-bound 승인을 전달합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:---plan}"
direction="${2:---to-edge}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
bundle="${3:-${repo_root}/target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-${version}}"
target="g7devops"
remote_stage=""

cleanup() {
  rc=$?
  trap - EXIT
  if [[ -n "${remote_stage}" ]]; then
    ssh "${target}" "rm -rf '${remote_stage}'" >/dev/null 2>&1 || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

usage() {
  echo "usage: $0 [--plan|--preflight|--apply] [--to-edge|--to-nginx] [release-bundle]"
}

[[ "${direction}" == "--to-edge" || "${direction}" == "--to-nginx" ]] || {
  usage >&2
  exit 2
}

echo "target: ssh ${target}"
echo "mode: ${mode}"
echo "direction: ${direction}"
echo "topology: public Nginx TLS -> VPSGuard 127.0.0.1:18080 -> Nginx 127.0.0.1:18081 -> PHP-FPM"
echo "preserve: SSH, certificates, G7 site data, public Nginx TLS and non-web listeners"
echo "rollback: Rust typed exact-file snapshot plus automatic rollback"

if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--preflight" || "${mode}" == "--apply" ]] || { usage >&2; exit 2; }

for required in \
  "${bundle}/BUILD-INFO.txt" \
  "${bundle}/SHA256SUMS" \
  "${bundle}/scripts/cutover-g7devops-remote.sh" \
  "${bundle}/g7devops/vps-guard.shadow.toml" \
  "${bundle}/g7devops/vps-guard.ingress.toml" \
  "${bundle}/g7devops/nginx/edge.conf" \
  "${bundle}/g7devops/nginx/bypass.conf"; do
  [[ -f "${required}" && ! -L "${required}" ]] || {
    echo "cutover input missing: ${required}" >&2
    exit 2
  }
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${bundle}" && sha256sum --check SHA256SUMS >/dev/null)
else
  (cd "${bundle}" && shasum -a 256 --check SHA256SUMS >/dev/null)
fi
commit="$(tail -1 "${bundle}/BUILD-INFO.txt")"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || { echo "release commit is invalid" >&2; exit 2; }
[[ "$(git -C "${repo_root}" rev-parse HEAD)" == "${commit}" ]] || {
  echo "release bundle does not match repository HEAD" >&2
  exit 2
}

remote_stage="$(ssh "${target}" 'umask 077; mktemp -d /tmp/vpsguard-cutover.XXXXXX')"
[[ "${remote_stage}" =~ ^/tmp/vpsguard-cutover\.[A-Za-z0-9]+$ ]] || {
  echo "unexpected remote staging path" >&2
  exit 1
}

scp -q \
  "${bundle}/BUILD-INFO.txt" \
  "${bundle}/SHA256SUMS" \
  "${bundle}/scripts/cutover-g7devops-remote.sh" \
  "${target}:${remote_stage}/"
scp -q "${bundle}/g7devops/vps-guard.shadow.toml" \
  "${target}:${remote_stage}/vps-guard.shadow.toml"
scp -q "${bundle}/g7devops/vps-guard.ingress.toml" \
  "${target}:${remote_stage}/vps-guard.ingress.toml"
scp -q "${bundle}/g7devops/nginx/edge.conf" \
  "${target}:${remote_stage}/g7devops-edge.conf"
scp -q "${bundle}/g7devops/nginx/bypass.conf" \
  "${target}:${remote_stage}/g7devops-bypass.conf"

if [[ "${mode}" == "--apply" ]]; then
  [[ "${VPS_GUARD_CUTOVER_CONFIRM:-}" == "g7devops:${direction#--}:${commit}" ]] || {
    echo "VPS_GUARD_CUTOVER_CONFIRM=g7devops:${direction#--}:${commit} is required" >&2
    exit 2
  }
fi

ssh "${target}" "sudo env \
VPS_GUARD_RELEASE_COMMIT='${commit}' \
VPS_GUARD_CUTOVER_CONFIRM='${VPS_GUARD_CUTOVER_CONFIRM:-}' \
bash '${remote_stage}/cutover-g7devops-remote.sh' '${mode}' '${direction}' '${remote_stage}'"
