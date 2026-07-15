#!/usr/bin/env bash
# shellcheck disable=SC2029 # remote paths are fixed or strict-regex validated before SSH expansion
set -euo pipefail

# OPS-009: g7devops의 root-only snapshot을 검증한 뒤 VPSGuard 소유 상태만 복구합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="g7devops"
mode="${1:---plan}"
snapshot_id="${2:-}"
snapshot_root="/var/backups/vps-guard/deployments"
remote_stage=""

cleanup() {
  if [[ -n "${remote_stage}" ]]; then
    ssh "${target}" "rm -rf '${remote_stage}'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

validate_snapshot_id() {
  [[ "$1" =~ ^deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
    echo "invalid deployment snapshot ID" >&2
    exit 2
  }
}

stage_restore_harness() {
  remote_stage="$(ssh "${target}" 'umask 077; mktemp -d /tmp/vpsguard-restore.XXXXXX')"
  [[ "${remote_stage}" =~ ^/tmp/vpsguard-restore\.[A-Za-z0-9]+$ ]] || {
    echo "unexpected remote staging path" >&2
    exit 1
  }
  scp -q "${repo_root}/scripts/deployment-state.sh" "${target}:${remote_stage}/deployment-state.sh"
  scp -q "${repo_root}/scripts/operation-lock.sh" "${target}:${remote_stage}/operation-lock.sh"
  ssh "${target}" "chmod 0700 '${remote_stage}/deployment-state.sh' '${remote_stage}/operation-lock.sh'"
}

case "${mode}" in
  --plan)
    echo "target: ssh ${target}"
    echo "mode: restore plan only"
    echo "snapshot root: ${snapshot_root}"
    echo "restore scope: VPSGuard-owned binary, unit, drop-in, config, token, service state and first-install directories"
    echo "preserve and verify: SSH, Nginx, certificates, G7 site and non-VPSGuard listeners"
    ;;
  --list)
    ssh "${target}" "sudo find '${snapshot_root}' -mindepth 1 -maxdepth 1 -type d -name 'deploy-*' -printf '%f\n' 2>/dev/null | LC_ALL=C sort"
    ;;
  --verify)
    validate_snapshot_id "${snapshot_id}"
    stage_restore_harness
    ssh "${target}" "sudo bash '${remote_stage}/deployment-state.sh' --verify '${snapshot_root}/${snapshot_id}'"
    ;;
  --apply)
    validate_snapshot_id "${snapshot_id}"
    [[ "${VPS_GUARD_RESTORE_CONFIRM:-}" == "g7devops:${snapshot_id}" ]] || {
      echo "VPS_GUARD_RESTORE_CONFIRM=g7devops:${snapshot_id} is required" >&2
      exit 2
    }
    stage_restore_harness
    ssh "${target}" "sudo bash -c \"source '${remote_stage}/operation-lock.sh'; operation_lock_acquire 'deployment-restore-${snapshot_id}'; VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot bash '${remote_stage}/deployment-state.sh' --restore '${snapshot_root}/${snapshot_id}'; operation_lock_release\""
    ssh "${target}" 'set -eu
sudo systemctl is-active --quiet nginx.service
sudo nginx -t >/dev/null
test -d /home/g7devops/public_html/public
sudo ss -H -ltn | awk "{print \$4}" | grep -Eq "(^|:)80$"
sudo ss -H -ltn | awk "{print \$4}" | grep -Eq "(^|:)443$"
echo "g7devops restore read-back: PASS"'
    ;;
  *)
    echo "usage: $0 [--plan|--list|--verify SNAPSHOT_ID|--apply SNAPSHOT_ID]" >&2
    exit 2
    ;;
esac
