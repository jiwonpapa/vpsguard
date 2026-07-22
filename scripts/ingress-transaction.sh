#!/usr/bin/env bash
set -euo pipefail

# OPS-003, OPS-004, OPS-010, NFR-009: candidate switch와 rollback은
# guard-system typed driver가 소유하며 이 파일은 legacy CLI adapter입니다.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

resolve_binary() {
  local candidate
  for candidate in \
    "${VPS_GUARD_OPERATION_BINARY:-}" \
    "${script_dir}/../bin/vps-guard"; do
    if [[ -n "${candidate}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
  if [[ -f "${repo_root}/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1 &&
    (cd "${repo_root}" && cargo build -q -p guard-cli); then
    printf '%s\n' "${repo_root}/target/debug/vps-guard"
    return
  fi
  if [[ -x /usr/local/bin/vps-guard ]]; then
    printf '%s\n' /usr/local/bin/vps-guard
    return
  fi
  echo "vps-guard operation binary is missing" >&2
  exit 2
}

direction="${1:---plan}"
mode="${2:---plan}"
case "${direction}" in
  --to-edge) direction_value="to-edge" ;;
  --to-nginx) direction_value="to-nginx" ;;
  --plan)
    echo "usage: $0 [--to-edge|--to-nginx] [--plan|--apply]"
    exit 0
    ;;
  *) echo "unknown direction: ${direction}" >&2; exit 2 ;;
esac

binary="$(resolve_binary)"
case "${mode}" in
  --plan) exec "${binary}" ops ingress-switch plan --direction "${direction_value}" ;;
  --apply) exec "${binary}" ops ingress-switch apply --direction "${direction_value}" ;;
  *) echo "expected --plan or --apply" >&2; exit 2 ;;
esac
