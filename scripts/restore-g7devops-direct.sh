#!/usr/bin/env bash
# shellcheck disable=SC2029 # validated snapshot IDs intentionally expand for the fixed SSH target
set -euo pipefail
# OPS-003, OPS-005, OPS-010, TLS-005: installed Rust driver가 checksum 검증,
# operation lock, public ingress restore와 자동 rollback을 소유합니다.
target="${VPS_GUARD_SSH_TARGET:-g7devops}"
mode="${1:---plan}"
snapshot_id="${2:-}"
snapshot_root="/var/backups/vps-guard/ingress"

validate_snapshot_id() {
  [[ "$1" =~ ^direct-[0-9]{8}T[0-9]{6}Z-[0-9]+-(direct|rollback)$ ]] || {
    echo "invalid direct snapshot ID" >&2
    exit 2
  }
}

case "${mode}" in
  --plan)
    echo "target: ssh ${target}"
    echo "snapshot root: ${snapshot_root}"
    echo "driver: installed guard-system typed transaction"
    ;;
  --list)
    ssh "${target}" "sudo find '${snapshot_root}' -mindepth 1 -maxdepth 1 -type d -name 'direct-*' -printf '%f\n' 2>/dev/null | LC_ALL=C sort"
    ;;
  --verify)
    validate_snapshot_id "${snapshot_id}"
    ssh "${target}" "sudo env VPS_GUARD_DIRECT_SNAPSHOT_ROOT='${snapshot_root}' /usr/local/bin/vps-guard ops ingress-state verify '${snapshot_root}/${snapshot_id}'"
    ;;
  --apply)
    validate_snapshot_id "${snapshot_id}"
    [[ "${VPS_GUARD_DIRECT_RESTORE_CONFIRM:-}" == "g7devops:${snapshot_id}" ]] || {
      echo "VPS_GUARD_DIRECT_RESTORE_CONFIRM=g7devops:${snapshot_id} is required" >&2
      exit 2
    }
    ssh "${target}" "sudo env VPS_GUARD_DIRECT_SNAPSHOT_ROOT='${snapshot_root}' VPS_GUARD_DIRECT_RESTORE_CONFIRM=restore-direct-snapshot /usr/local/bin/vps-guard ops ingress-state restore '${snapshot_root}/${snapshot_id}'"
    ;;
  *)
    echo "usage: $0 --plan | --list | --verify SNAPSHOT_ID | --apply SNAPSHOT_ID" >&2
    exit 2
    ;;
esac
