#!/usr/bin/env bash
set -euo pipefail

# OPS-003, OPS-005, OPS-009, TLS-005: 성공한 direct TLS 전환도 별도 snapshot으로
# 복구할 수 있고, 복구 실패는 현재 상태로 되돌아가야 합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

root="${fixture}/root"
snapshots="${fixture}/snapshots"
state="${fixture}/state"
mkdir -p \
  "${root}/etc/nginx/sites-available" \
  "${root}/etc/nginx/sites-enabled" \
  "${root}/etc/vps-guard" \
  "${root}/etc/systemd/system/vps-guard-edge.service.d" \
  "${root}/etc/letsencrypt/renewal-hooks/deploy" \
  "${root}/usr/local/libexec/vps-guard" \
  "${root}/etc/letsencrypt/live/g7devops.com" \
  "${state}" "${snapshots}"

printf 'nginx-before\n' >"${root}/etc/nginx/sites-available/g7.conf"
printf 'config-before\n' >"${root}/etc/vps-guard/config.toml"
printf 'deny-before\n' >"${root}/etc/nginx/sites-available/g7-default-deny.conf"
ln -s /etc/nginx/sites-available/g7-default-deny.conf \
  "${root}/etc/nginx/sites-enabled/g7-default-deny.conf"
printf 'active\n' >"${state}/vps-guard-edge.service.active"
printf 'enabled\n' >"${state}/vps-guard-edge.service.enabled"
printf 'active\n' >"${state}/nginx.service.active"
printf 'enabled\n' >"${state}/nginx.service.enabled"

snapshot_output="$(
  VPS_GUARD_TEST_ROOT="${root}" \
  VPS_GUARD_DIRECT_SNAPSHOT_ROOT="${snapshots}" \
  VPS_GUARD_FAKE_STATE_DIR="${state}" \
  bash "${repo_root}/scripts/g7devops-direct-state.sh" --snapshot direct
)"
snapshot="${snapshot_output#snapshot=}"
[[ -d "${snapshot}" && -f "${snapshot}/SHA256SUMS" ]]

printf 'nginx-direct\n' >"${root}/etc/nginx/sites-available/g7.conf"
printf 'config-direct\n' >"${root}/etc/vps-guard/config.toml"
rm -f "${root}/etc/nginx/sites-enabled/g7-default-deny.conf"

VPS_GUARD_TEST_ROOT="${root}" \
VPS_GUARD_DIRECT_SNAPSHOT_ROOT="${snapshots}" \
VPS_GUARD_FAKE_STATE_DIR="${state}" \
VPS_GUARD_DIRECT_RESTORE_CONFIRM="restore-direct-snapshot" \
  bash "${repo_root}/scripts/g7devops-direct-state.sh" --restore "${snapshot}"

grep -Fxq 'nginx-before' "${root}/etc/nginx/sites-available/g7.conf"
grep -Fxq 'config-before' "${root}/etc/vps-guard/config.toml"
[[ -L "${root}/etc/nginx/sites-enabled/g7-default-deny.conf" ]]
grep -Fxq active "${state}/vps-guard-edge.service.active"

printf 'nginx-current\n' >"${root}/etc/nginx/sites-available/g7.conf"
printf 'config-current\n' >"${root}/etc/vps-guard/config.toml"
if VPS_GUARD_TEST_ROOT="${root}" \
  VPS_GUARD_DIRECT_SNAPSHOT_ROOT="${snapshots}" \
  VPS_GUARD_FAKE_STATE_DIR="${state}" \
  VPS_GUARD_TEST_CUTOVER_SECONDS=6 \
  VPS_GUARD_DIRECT_RESTORE_CONFIRM="restore-direct-snapshot" \
    bash "${repo_root}/scripts/g7devops-direct-state.sh" --restore "${snapshot}" \
    >/dev/null 2>&1; then
  echo "direct restore accepted a cutover over 5 seconds" >&2
  exit 1
fi
grep -Fxq 'nginx-current' "${root}/etc/nginx/sites-available/g7.conf"
grep -Fxq 'config-current' "${root}/etc/vps-guard/config.toml"

echo "direct state harness: PASS"
