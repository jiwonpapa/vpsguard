#!/usr/bin/env bash
# shellcheck disable=SC2029 # fixed target and regex-validated values are intentionally expanded for SSH
set -euo pipefail

# OPS-001, OPS-002, OPS-005, OPS-009, SEC-001: g7devops에 checksum 검증된
# observe-only shadow를 설치하고 모든 실패를 pre-deploy snapshot으로 복구합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:---plan}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
bundle="${2:-${repo_root}/target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-${version}}"
config="${3:-${repo_root}/configs/vps-guard.g7devops.shadow.toml}"
token_file="${VPS_GUARD_CLOUDFLARE_TOKEN_FILE:-${repo_root}/secrets/cloudflare-token}"
target="g7devops"
remote_stage=""
snapshot=""
completed=false

cleanup_and_restore() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ ${rc} -ne 0 && -n "${snapshot}" && "${completed}" != true ]]; then
    echo "deployment failed; restoring pre-deploy snapshot" >&2
    if ! ssh "${target}" \
      "sudo env VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot bash '${remote_stage}/bundle/scripts/deployment-state.sh' --restore '${snapshot}'"; then
      echo "automatic restore failed; run scripts/restore-g7devops.sh with snapshot $(basename "${snapshot}")" >&2
    fi
  fi
  if [[ -n "${remote_stage}" ]]; then
    ssh "${target}" "rm -rf '${remote_stage}'" >/dev/null 2>&1 || true
  fi
  exit "${rc}"
}
trap cleanup_and_restore EXIT

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

verify_local_bundle() {
  [[ -d "${bundle}" && -f "${bundle}/SHA256SUMS" && -f "${bundle}/BUILD-INFO.txt" ]] || {
    echo "verified Linux release bundle is required: ${bundle}" >&2
    exit 2
  }
  for binary in vps-guard vps-guard-control vps-guard-edge; do
    [[ -x "${bundle}/bin/${binary}" ]]
  done
  for required in \
    "${bundle}/scripts/deployment-state.sh" \
    "${bundle}/scripts/update-release.sh" \
    "${bundle}/systemd/vps-guard-control.service" \
    "${bundle}/systemd/vps-guard-edge.service" \
    "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf"; do
    [[ -f "${required}" ]] || { echo "bundle file missing: ${required}" >&2; exit 2; }
  done
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${bundle}" && sha256sum --check SHA256SUMS)
  else
    (cd "${bundle}" && shasum -a 256 --check SHA256SUMS)
  fi
  grep -Fxq 'target=x86_64-unknown-linux-gnu' "${bundle}/BUILD-INFO.txt"
}

verify_local_config() {
  [[ -f "${config}" && ! -L "${config}" ]] || { echo "shadow config file is required" >&2; exit 2; }
  grep -Eq '^http_bind = "127\.0\.0\.1:[0-9]+"$' "${config}"
  grep -Fxq 'mode = "observe"' "${config}"
  grep -Fxq 'enabled = false' "${config}"
  edge_host="$(sed -n 's/^canonical_host = "\([^"]*\)"/\1/p' "${config}" | head -1)"
  [[ "${edge_host}" =~ ^[A-Za-z0-9.-]+$ ]] || {
    echo "shadow config requires a safe canonical Host" >&2
    exit 2
  }
}

verify_local_token() {
  [[ -f "${token_file}" && ! -L "${token_file}" && -s "${token_file}" ]] || {
    echo "root-only Cloudflare token file is required" >&2
    exit 2
  }
  [[ "$(file_mode "${token_file}")" == 600 ]] || {
    echo "Cloudflare token file must have mode 0600" >&2
    exit 2
  }
  [[ "$(wc -c <"${token_file}" | tr -d ' ')" -le 4096 ]] || {
    echo "Cloudflare token file is too large" >&2
    exit 2
  }
  LC_ALL=C grep -Eq '^[A-Za-z0-9_-]+$' "${token_file}" || {
    echo "Cloudflare token file must contain one token line" >&2
    exit 2
  }
}

stage_candidate() {
  remote_stage="$(ssh "${target}" 'umask 077; mktemp -d /tmp/vpsguard-shadow.XXXXXX')"
  [[ "${remote_stage}" =~ ^/tmp/vpsguard-shadow\.[A-Za-z0-9]+$ ]] || {
    echo "unexpected remote staging path" >&2
    exit 1
  }
  ssh "${target}" "mkdir -p '${remote_stage}/bundle'"
  scp -qr "${bundle}/." "${target}:${remote_stage}/bundle/"
  scp -q "${config}" "${target}:${remote_stage}/config.toml"
}

remote_preflight() {
  ssh "${target}" "set -eu
test \"\$(uname -m)\" = x86_64
grep -Fxq 'ID=ubuntu' /etc/os-release
grep -Eq '^VERSION_ID=\"?24\\.04\"?$' /etc/os-release
awk '/MemTotal/ { exit !(\$2 * 1024 >= 1800000000) }' /proc/meminfo
sudo -n true
sudo systemctl is-active --quiet nginx.service
sudo systemctl is-active --quiet php8.5-fpm.service
sudo systemctl is-active --quiet mysql.service
sudo systemctl is-active --quiet redis-server.service
sudo systemctl is-active --quiet g7-queue.service
sudo systemctl is-active --quiet g7-reverb.service
! sudo systemctl is-failed --quiet g7-scheduler.service
test -d /home/g7devops/public_html/public
sudo test -f /etc/nginx/sites-enabled/g7.conf
sudo nginx -t >/dev/null
sudo ss -H -ltn | awk '{print \$4}' | grep -Eq '(^|:)80$'
sudo ss -H -ltn | awk '{print \$4}' | grep -Eq '(^|:)443$'
sudo ss -H -ltn | awk '{print \$4}' | grep -Eq '(^|:)8080$'
status=\$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: ${edge_host}' http://127.0.0.1:8080/)
test \"\${status}\" -gt 0
test \"\${status}\" -lt 500
cd '${remote_stage}/bundle'
sha256sum --check SHA256SUMS >/dev/null
grep -Fxq 'target=x86_64-unknown-linux-gnu' BUILD-INFO.txt
./bin/vps-guard check-config --config '${remote_stage}/config.toml' >/dev/null
if sudo test -e /etc/vps-guard/config.toml; then
  sudo test -f /etc/vps-guard/config.toml
  sudo test ! -L /etc/vps-guard/config.toml
  sudo cmp -s '${remote_stage}/config.toml' /etc/vps-guard/config.toml
else
  ! sudo ss -H -ltn | awk '{print \$4}' | grep -Eq '(^|:)(7727|18080)$'
fi
echo 'g7devops preflight: PASS'
echo 'target=ubuntu-24.04,x86_64,2gb'
echo 'origin=127.0.0.1:8080,php8.5-fpm'"
}

echo "target: ssh ${target}"
echo "mode: shadow deployment with exact restore"
echo "bundle: ${bundle}"
echo "config candidate: ${config}"
echo "preserve: SSH, Nginx public 80/443, certificates, G7 site data and non-web listeners"
echo "secret transport: stdin to root-only systemd credential source; never bundle, argv, log or evidence"

if [[ "${mode}" == "--plan" ]]; then
  echo "next: --preflight performs read-only target verification; --apply requires commit-bound confirmation"
  exit 0
fi
if [[ "${mode}" != "--preflight" && "${mode}" != "--apply" ]]; then
  echo "usage: $0 [--plan|--preflight|--apply] [bundle-directory] [shadow-config]" >&2
  exit 2
fi

verify_local_bundle
verify_local_config
stage_candidate
remote_preflight

if [[ "${mode}" == "--preflight" ]]; then
  exit 0
fi

verify_local_token
git_commit="$(tail -1 "${bundle}/BUILD-INFO.txt")"
[[ "${git_commit}" =~ ^[0-9a-f]{40}$ ]] || { echo "bundle git commit is invalid" >&2; exit 2; }
[[ "${VPS_GUARD_DEPLOY_CONFIRM:-}" == "g7devops-shadow:${git_commit}" ]] || {
  echo "VPS_GUARD_DEPLOY_CONFIRM=g7devops-shadow:${git_commit} is required" >&2
  exit 2
}

snapshot_output="$(
  ssh "${target}" "sudo bash '${remote_stage}/bundle/scripts/deployment-state.sh' --snapshot"
)"
snapshot="${snapshot_output#snapshot=}"
[[ "${snapshot}" =~ ^/var/backups/vps-guard/deployments/deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
  echo "pre-deploy snapshot was not created" >&2
  exit 1
}

ssh "${target}" "set -eu
sudo id -u vps-guard >/dev/null 2>&1 || sudo useradd --system --home /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard
sudo install -d -m 0750 -o root -g vps-guard /etc/vps-guard
if sudo test -e /etc/vps-guard/config.toml; then
  sudo test -f /etc/vps-guard/config.toml
  sudo test ! -L /etc/vps-guard/config.toml
  sudo cmp -s '${remote_stage}/config.toml' /etc/vps-guard/config.toml
else
  sudo install -m 0640 -o root -g vps-guard '${remote_stage}/config.toml' /etc/vps-guard/config.toml
fi"

ssh "${target}" "set -eu
umask 077
token_tmp=\$(mktemp '${remote_stage}/cloudflare-token.XXXXXX')
trap 'rm -f \"\${token_tmp}\"' EXIT
cat >\"\${token_tmp}\"
sudo install -d -m 0700 -o root -g root /etc/vps-guard/secrets
if sudo test -e /etc/vps-guard/secrets/cloudflare-token; then
  sudo test -f /etc/vps-guard/secrets/cloudflare-token
  sudo test ! -L /etc/vps-guard/secrets/cloudflare-token
  sudo cmp -s \"\${token_tmp}\" /etc/vps-guard/secrets/cloudflare-token
else
  sudo install -m 0600 -o root -g root \"\${token_tmp}\" /etc/vps-guard/secrets/cloudflare-token
fi
sudo test \"\$(sudo stat -c '%U:%G:%a' /etc/vps-guard/secrets/cloudflare-token)\" = 'root:root:600'" <"${token_file}"

ssh "${target}" "sudo env \
VPS_GUARD_UPDATE_CONFIRM=update-with-rollback \
VPS_GUARD_EDGE_HOST='${edge_host}' \
bash '${remote_stage}/bundle/scripts/update-release.sh' --apply '${remote_stage}/bundle'"

ssh "${target}" "set -eu
sudo systemctl enable vps-guard-control.service vps-guard-edge.service >/dev/null
curl --disable --fail --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 http://127.0.0.1:7727/health/live >/dev/null
status=\$(curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 --output /dev/null --write-out '%{http_code}' -H 'Host: ${edge_host}' http://127.0.0.1:18080/)
test \"\${status}\" -gt 0
test \"\${status}\" -lt 500
curl --disable --fail --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 -H 'Host: ${edge_host}' http://127.0.0.1:18080/health/ready >/dev/null
sudo bash '${remote_stage}/bundle/scripts/deployment-state.sh' --verify '${snapshot}' >/dev/null
sudo systemctl is-active --quiet nginx.service
sudo nginx -t >/dev/null
echo 'g7devops shadow deployment read-back: PASS'"

completed=true
echo "shadow deployment complete"
echo "snapshot=$(basename "${snapshot}")"
echo "public 80/443, Nginx, Cloudflare mode and G7 site were not changed"
