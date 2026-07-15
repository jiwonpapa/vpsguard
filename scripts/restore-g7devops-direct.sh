#!/usr/bin/env bash
# shellcheck disable=SC2029 # strict-regex validated remote paths are intentionally expanded remotely
set -euo pipefail

# OPS-003, OPS-005, OPS-009, TLS-005: 성공한 g7devops direct TLS 전환을
# checksum snapshot으로 검증한 뒤 이전 ingress와 service 상태로 되돌립니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${VPS_GUARD_SSH_TARGET:-g7devops}"
mode="${1:---plan}"
snapshot_id="${2:-}"
snapshot_root="/var/backups/vps-guard/ingress"
remote_stage=""

cleanup() {
  if [[ -n "${remote_stage}" ]]; then
    ssh "${target}" "rm -rf -- '${remote_stage}'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

validate_snapshot_id() {
  [[ "$1" =~ ^direct-[0-9]{8}T[0-9]{6}Z-[0-9]+-(direct|rollback)$ ]] || {
    echo "invalid direct snapshot ID" >&2
    exit 2
  }
}

stage_harness() {
  remote_stage="$(ssh "${target}" 'umask 077; mktemp -d /tmp/vpsguard-direct-restore.XXXXXX')"
  [[ "${remote_stage}" =~ ^/tmp/vpsguard-direct-restore\.[A-Za-z0-9]+$ ]]
  scp -q "${repo_root}/scripts/g7devops-direct-state.sh" \
    "${target}:${remote_stage}/direct-state.sh"
  scp -q "${repo_root}/scripts/operation-lock.sh" \
    "${target}:${remote_stage}/operation-lock.sh"
  ssh "${target}" "chmod 0700 '${remote_stage}/direct-state.sh' '${remote_stage}/operation-lock.sh'"
}

case "${mode}" in
  --plan)
    echo "target: ssh ${target}"
    echo "snapshot root: ${snapshot_root}"
    echo "restore: VPSGuard/Nginx service stop -> exact state replacement -> saved-order restart"
    echo "run before first-install deployment restore or uninstall"
    ;;
  --list)
    ssh "${target}" "sudo find '${snapshot_root}' -mindepth 1 -maxdepth 1 -type d -name 'direct-*' -printf '%f\n' 2>/dev/null | LC_ALL=C sort"
    ;;
  --verify)
    validate_snapshot_id "${snapshot_id}"
    stage_harness
    ssh "${target}" "sudo env VPS_GUARD_DIRECT_SNAPSHOT_ROOT='${snapshot_root}' bash '${remote_stage}/direct-state.sh' --verify '${snapshot_root}/${snapshot_id}'"
    ;;
  --apply)
    validate_snapshot_id "${snapshot_id}"
    [[ "${VPS_GUARD_DIRECT_RESTORE_CONFIRM:-}" == "g7devops:${snapshot_id}" ]] || {
      echo "VPS_GUARD_DIRECT_RESTORE_CONFIRM=g7devops:${snapshot_id} is required" >&2
      exit 2
    }
    stage_harness
    ssh "${target}" "sudo bash -c \"source '${remote_stage}/operation-lock.sh'; operation_lock_acquire 'direct-restore-${snapshot_id}'; VPS_GUARD_DIRECT_SNAPSHOT_ROOT='${snapshot_root}' VPS_GUARD_DIRECT_RESTORE_CONFIRM=restore-direct-snapshot bash '${remote_stage}/direct-state.sh' --restore '${snapshot_root}/${snapshot_id}'; operation_lock_release\""
    ;;
  *)
    echo "usage: $0 --plan | --list | --verify SNAPSHOT_ID | --apply SNAPSHOT_ID" >&2
    exit 2
    ;;
esac
