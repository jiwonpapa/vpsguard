#!/usr/bin/env bash
set -euo pipefail

# EDGE-001, EDGE-002, TLS-005, OPS-003, OPS-010: staged direct TLS 후보의
# root mutation과 rollback은 installed Rust OperationDriver만 수행합니다.
stage="${1:-}"
[[ "${EUID}" -eq 0 ]] || { echo "root is required" >&2; exit 2; }
[[ "${stage}" =~ ^/tmp/vpsguard-direct\.[A-Za-z0-9]+$ ]] || {
  echo "invalid staging path" >&2
  exit 2
}
[[ "${VPS_GUARD_DIRECT_CONFIRM:-}" == "g7devops:direct-tls" ]] || {
  echo "VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls is required" >&2
  exit 2
}
exec /usr/local/bin/vps-guard ops ingress-state apply-direct --stage "${stage}"
