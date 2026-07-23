#!/usr/bin/env bash
set -euo pipefail
# OPS-005, OPS-009: 검증된 bundle만 설치하고 실패하면 배포 snapshot으로 복구합니다.
mode="${1:---plan}"
bundle="${2:-}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=operation-lock.sh
source "${script_dir}/operation-lock.sh"
manifest_name="ownership-manifest.txt"
health_url="${VPS_GUARD_CONTROL_HEALTH_URL:-http://127.0.0.1:7727/health/live}"
edge_health_url="${VPS_GUARD_EDGE_HEALTH_URL:-http://127.0.0.1:18080/health/live}"
edge_host="${VPS_GUARD_EDGE_HOST:-}"
snapshot=""
release_id=""
release_dir=""
release_created=false
operation_started=0
wait_for_http() {
  curl --disable --fail --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
    --connect-timeout 1 --max-time 15 "$@"
}
atomic_symlink() {
  local target="$1"
  local link="$2"
  local temporary="${link}.vpsguard-new-$$"
  rm -f "${temporary}"
  ln -s "${target}" "${temporary}"
  mv -Tf "${temporary}" "${link}"
}
echo "mode: ${mode}"
echo "bundle: ${bundle:-<required for apply>}"
echo "preserve: /etc/vps-guard, /var/lib/vps-guard, /etc/letsencrypt, Nginx site data"
echo "replacement: stage versioned release, atomically switch current symlink, restart control then edge"
if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { echo "usage: $0 [--plan|--apply] [bundle]" >&2; exit 2; }
[[ "${VPS_GUARD_UPDATE_CONFIRM:-}" == "update-with-rollback" ]] || {
  echo "VPS_GUARD_UPDATE_CONFIRM=update-with-rollback is required" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || { echo "root is required for update" >&2; exit 2; }
[[ -d "${bundle}" ]] || { echo "bundle directory is required" >&2; exit 2; }
[[ -n "${edge_host}" ]] || { echo "VPS_GUARD_EDGE_HOST is required" >&2; exit 2; }
[[ "${edge_host}" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "invalid edge Host" >&2; exit 2; }
if ss -H -ltnp 2>/dev/null | grep -Eq '(0\.0\.0\.0|\*):443.*vps-guard-edge'; then
  echo "public edge update is blocked until Nginx bypass owns 443" >&2
  echo "next: enable bypass and verify HTTPS before running update" >&2
  exit 2
fi
(cd "${bundle}" && sha256sum --check SHA256SUMS)
for binary in vps-guard vps-guard-control vps-guard-privileged vps-guard-edge; do
  [[ -x "${bundle}/bin/${binary}" ]]
done
for required in \
  "${bundle}/systemd/vps-guard-control.service" \
  "${bundle}/systemd/vps-guard-privileged.service" \
  "${bundle}/systemd/vps-guard-privileged.socket" \
  "${bundle}/systemd/vps-guard-edge.service" \
  "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf" \
  "${bundle}/tmpfiles/vps-guard.conf" \
  "${bundle}/scripts/deployment-state.sh" \
  "${bundle}/scripts/state-common.sh" \
  "${bundle}/scripts/operation-lock.sh" \
  "${bundle}/BUILD-INFO.txt" \
  "${bundle}/${manifest_name}"; do
  [[ -f "${required}" ]] || { echo "bundle file missing: ${required}" >&2; exit 2; }
done
release_id="$(tail -1 "${bundle}/BUILD-INFO.txt")"
[[ "${release_id}" =~ ^[0-9a-f]{40}$ ]] || { echo "release commit is invalid" >&2; exit 2; }
operation_lock_acquire "update-$$"
operation_started="${SECONDS}"
operation_progress preflight completed
snapshot_output="$(bash "${bundle}/scripts/deployment-state.sh" --snapshot)"
snapshot="${snapshot_output#snapshot=}"
[[ "${snapshot}" =~ ^/var/backups/vps-guard/deployments/deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
  echo "deployment snapshot was not created" >&2
  exit 1
}
rollback() {
  local rc=$?
  local rollback_started="${SECONDS}"
  if [[ ${rc} -eq 0 ]]; then
    return
  fi
  echo "update failed; restoring deployment snapshot" >&2
  operation_progress rollback started
  VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
    bash "${bundle}/scripts/deployment-state.sh" --restore "${snapshot}" || \
    echo "automatic update restore failed; snapshot=${snapshot}" >&2
  if [[ "${release_created}" == true && -n "${release_dir}" ]]; then
    rm -rf -- "${release_dir}"
  fi
  if (( SECONDS - rollback_started > 10 )); then
    echo "automatic update rollback exceeded 10 seconds" >&2
  fi
  operation_progress rollback completed
  operation_lock_release
  exit "${rc}"
}
trap rollback EXIT
release_root="/usr/local/lib/vps-guard/releases"
release_dir="${release_root}/${release_id}"
if [[ -L "/usr/local/lib/vps-guard" || -L "${release_root}" || -L "${release_dir}" ]]; then
  echo "release path must not be a symlink" >&2
  exit 1
fi
if [[ -e "${release_dir}" && ! -d "${release_dir}" ]]; then
  echo "release path is not a directory: ${release_dir}" >&2
  exit 1
fi
if [[ ! -d "${release_dir}" ]]; then
  stage_dir="${release_root}/.${release_id}.stage-$$"
  [[ ! -e "${stage_dir}" ]] || { echo "release stage already exists" >&2; exit 1; }
  install -d -m 0755 "${stage_dir}/bin"
  for binary in vps-guard vps-guard-control vps-guard-privileged vps-guard-edge; do
    install -m 0755 "${bundle}/bin/${binary}" "${stage_dir}/bin/${binary}"
  done
  mv "${stage_dir}" "${release_dir}"
  release_created=true
else
  for binary in vps-guard vps-guard-control vps-guard-privileged vps-guard-edge; do
    cmp -s "${bundle}/bin/${binary}" "${release_dir}/bin/${binary}" || {
      echo "existing release content mismatch: ${binary}" >&2
      exit 1
    }
  done
fi
"${release_dir}/bin/vps-guard" check-config --config /etc/vps-guard/config.toml
operation_progress stage_release completed

install -d -m 0755 /usr/local/libexec/vps-guard
install -m 0755 "${bundle}/scripts/deployment-state.sh" /usr/local/libexec/vps-guard/deployment-state
install -m 0644 "${bundle}/scripts/state-common.sh" /usr/local/libexec/vps-guard/state-common.sh
install -m 0644 "${bundle}/systemd/vps-guard-control.service" /etc/systemd/system/vps-guard-control.service
install -m 0644 "${bundle}/systemd/vps-guard-privileged.service" /etc/systemd/system/vps-guard-privileged.service
install -m 0644 "${bundle}/systemd/vps-guard-privileged.socket" /etc/systemd/system/vps-guard-privileged.socket
install -m 0644 "${bundle}/systemd/vps-guard-edge.service" /etc/systemd/system/vps-guard-edge.service
if [[ -f /etc/vps-guard/secrets/cloudflare-token ]]; then
  install -d -m 0755 /etc/systemd/system/vps-guard-control.service.d
  install -m 0644 \
    "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf" \
    /etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf
fi
install -m 0644 "${bundle}/tmpfiles/vps-guard.conf" /usr/lib/tmpfiles.d/vps-guard.conf
install -d -m 0750 /var/lib/vps-guard
install -m 0644 "${bundle}/${manifest_name}" /var/lib/vps-guard/ownership-manifest.txt
systemctl daemon-reload

systemctl stop vps-guard-edge.service vps-guard-control.service \
  vps-guard-privileged.service vps-guard-privileged.socket
install -d -m 0755 /usr/local/lib/vps-guard /usr/local/bin
atomic_symlink "${release_dir}" /usr/local/lib/vps-guard/current
for binary in vps-guard vps-guard-control vps-guard-privileged vps-guard-edge; do
  atomic_symlink "/usr/local/lib/vps-guard/current/bin/${binary}" "/usr/local/bin/${binary}"
done
/usr/local/bin/vps-guard check-config --config /etc/vps-guard/config.toml
systemctl start vps-guard-privileged.socket vps-guard-privileged.service
systemctl start vps-guard-control.service
wait_for_http "${health_url}" >/dev/null
systemctl start vps-guard-edge.service
wait_for_http -H "Host: ${edge_host}" "${edge_health_url}" >/dev/null
bash "${bundle}/scripts/deployment-state.sh" --verify "${snapshot}" >/dev/null
if (( SECONDS - operation_started > 60 )); then
  echo "update exceeded 60 seconds" >&2
  false
fi
operation_progress verify completed
operation_lock_release
trap - EXIT
echo "update complete; snapshot=${snapshot}"
