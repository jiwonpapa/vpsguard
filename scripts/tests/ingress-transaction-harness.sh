#!/usr/bin/env bash
set -euo pipefail

# OPS-003, OPS-004, TLS-005: 양방향 전환과 정확 rollback을 fixture에서 검증합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
root="$(mktemp -d)"
output="${root}/failure.log"
trap 'rm -rf "${root}"' EXIT
active_logical="/etc/nginx/conf.d/vps-guard-ingress.conf" edge_logical="/etc/vps-guard/nginx/edge-origin.conf" bypass_logical="/etc/vps-guard/nginx/public-bypass.conf"
active="${root}${active_logical}"
edge="${root}${edge_logical}"
bypass="${root}${bypass_logical}"
guard="${root}/etc/vps-guard/config.toml"
state_dir="${root}/state"
mkdir -p "$(dirname "${active}")" "$(dirname "${edge}")" "${state_dir}"
printf 'edge-candidate\n' >"${edge}"
printf 'nginx-bypass\n' >"${bypass}"
cp "${bypass}" "${active}"
printf 'fixture-config\n' >"${guard}"
printf 'inactive\n' >"${state_dir}/vps-guard-edge.service.active"
printf 'enabled\n' >"${state_dir}/vps-guard-edge.service.enabled"
printf 'false\n' >"${state_dir}/edge-public"
printf 'absent\n' >"${state_dir}/public-edge-header"
printf 'LISTEN 0 128 0.0.0.0:22 users:sshd\n' >"${state_dir}/protected-listeners"
run_transaction() {
  env \
    VPS_GUARD_TEST_ROOT="${root}" \
    VPS_GUARD_FAKE_STATE_DIR="${state_dir}" \
    VPS_GUARD_BACKUP_ROOT="${root}/backups" \
    VPS_GUARD_NGINX_ACTIVE="${active_logical}" \
    VPS_GUARD_NGINX_EDGE_CANDIDATE="${edge_logical}" \
    VPS_GUARD_NGINX_BYPASS_CANDIDATE="${bypass_logical}" \
    VPS_GUARD_INGRESS_CONFIRM="${1#--}" \
    VPS_GUARD_INGRESS_PROBE_URL="https://fixture.example/" \
    bash "${repo_root}/scripts/ingress-transaction.sh" "$1" --apply
}

run_transaction --to-edge >/dev/null
cmp -s "${active}" "${edge}"
grep -Fxq active "${state_dir}/vps-guard-edge.service.active"

run_transaction --to-nginx >/dev/null
cmp -s "${active}" "${bypass}"
grep -Fxq inactive "${state_dir}/vps-guard-edge.service.active"

if VPS_GUARD_FAKE_CURL_FAIL=1 run_transaction --to-edge >"${output}" 2>&1; then
  echo "probe failure must fail ingress transaction" >&2
  exit 1
fi
grep -Fq 'rollback_succeeded=true' "${output}"
cmp -s "${active}" "${bypass}"
grep -Fxq inactive "${state_dir}/vps-guard-edge.service.active"

echo "ingress transaction harness: PASS"
