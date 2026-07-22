#!/usr/bin/env bash
set -euo pipefail

# OPS-003, OPS-005, OPS-010, NFR-009: public ingress mutation은 guard-system의
# typed OperationDriver가 소유합니다. 이 파일은 legacy 호출 규약만 보존합니다.
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

binary="$(resolve_binary)"
mode="${1:---plan}"
snapshot="${2:-}"

case "${mode}" in
  --plan)
    exec "${binary}" ops ingress-state plan
    ;;
  --snapshot)
    exec "${binary}" ops ingress-state snapshot --label "${snapshot:-direct}"
    ;;
  --verify)
    [[ -n "${snapshot}" && $# -eq 2 ]] || exit 2
    exec "${binary}" ops ingress-state verify "${snapshot}"
    ;;
  --restore)
    [[ -n "${snapshot}" && $# -eq 2 ]] || exit 2
    exec "${binary}" ops ingress-state restore "${snapshot}"
    ;;
  *)
    echo "usage: $0 [--plan|--snapshot [direct|rollback]|--verify SNAPSHOT|--restore SNAPSHOT]" >&2
    exit 2
    ;;
esac
