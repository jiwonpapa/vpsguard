#!/usr/bin/env bash
set -euo pipefail

# OPS-003, OPS-004, TLS-005: edge·Nginx 양방향 전환과 probe 실패 시 active
# config·edge service 상태의 정확 복구를 격리 fixture에서 검증합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_bin="${repo_root}/scripts/tests/fixtures/ingress-bin"
root="$(mktemp -d)"
output="$(mktemp)"
trap 'rm -rf "${root}"; rm -f "${output}"' EXIT

active_logical="/etc/nginx/conf.d/vps-guard-ingress.conf"
edge_logical="/etc/vps-guard/nginx/edge-origin.conf"
bypass_logical="/etc/vps-guard/nginx/public-bypass.conf"
active="${root}${active_logical}"
edge="${root}${edge_logical}"
bypass="${root}${bypass_logical}"
state_dir="${root}/state"
mkdir -p "$(dirname "${active}")" "$(dirname "${edge}")" "${state_dir}"
printf 'edge-candidate\n' >"${edge}"
printf 'nginx-bypass\n' >"${bypass}"
cp "${bypass}" "${active}"
printf 'inactive\n' >"${state_dir}/vps-guard-edge.service"

run_transaction() {
  env \
    PATH="${fixture_bin}:${PATH}" \
    VPS_GUARD_TEST_ROOT="${root}" \
    VPS_GUARD_FAKE_STATE_DIR="${state_dir}" \
    VPS_GUARD_NGINX_ACTIVE="${active_logical}" \
    VPS_GUARD_NGINX_EDGE_CANDIDATE="${edge_logical}" \
    VPS_GUARD_NGINX_BYPASS_CANDIDATE="${bypass_logical}" \
    VPS_GUARD_INGRESS_CONFIRM="${1#--}" \
    VPS_GUARD_INGRESS_PROBE_URL="https://fixture.example/" \
    bash "${repo_root}/scripts/ingress-transaction.sh" "$1" --apply
}

run_transaction --to-edge >/dev/null
cmp -s "${active}" "${edge}"
grep -Fxq active "${state_dir}/vps-guard-edge.service"

run_transaction --to-nginx >/dev/null
cmp -s "${active}" "${bypass}"
grep -Fxq inactive "${state_dir}/vps-guard-edge.service"

if VPS_GUARD_FAKE_CURL_FAIL=1 run_transaction --to-edge >"${output}" 2>&1; then
  echo "probe failure must fail ingress transaction" >&2
  exit 1
fi
grep -Fq 'ingress transaction failed; restoring snapshot' "${output}"
cmp -s "${active}" "${bypass}"
grep -Fxq inactive "${state_dir}/vps-guard-edge.service"

echo "ingress transaction harness: PASS"
