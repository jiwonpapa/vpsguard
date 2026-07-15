#!/usr/bin/env bash
set -euo pipefail

# OPS-002, OPS-005, OPS-009, SEC-001, TLS-005, ACT-010: first-install
# snapshot은 기존 파일과 부재 상태를 정확히 복구하고 보호 경계를 변경하지 않습니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

root="${fixture}/root"
snapshots="${fixture}/snapshots"
mkdir -p \
  "${root}/usr/local/bin" \
  "${root}/etc/vps-guard/secrets" \
  "${root}/etc/nginx/sites-enabled" \
  "${root}/etc/ssh" \
  "${root}/etc/letsencrypt/live/example" \
  "${root}/home/g7devops/public_html/app" \
  "${root}/.vpsguard-test/systemd"

printf 'old-binary\n' >"${root}/usr/local/bin/vps-guard"
printf 'old-config\n' >"${root}/etc/vps-guard/config.toml"
printf 'fixture-old-token\n' >"${root}/etc/vps-guard/secrets/cloudflare-token"
chmod 0600 "${root}/etc/vps-guard/secrets/cloudflare-token"
printf 'nginx-original\n' >"${root}/etc/nginx/sites-enabled/g7.conf"
printf 'ssh-original\n' >"${root}/etc/ssh/sshd_config"
printf 'certificate-original\n' >"${root}/etc/letsencrypt/live/example/fullchain.pem"
printf 'site-original\n' >"${root}/home/g7devops/public_html/app/index.php"
printf 'enabled\n' >"${root}/.vpsguard-test/systemd/vps-guard-control.service.enabled"
printf 'active\n' >"${root}/.vpsguard-test/systemd/vps-guard-control.service.active"
printf 'disabled\n' >"${root}/.vpsguard-test/systemd/vps-guard-edge.service.enabled"
printf 'inactive\n' >"${root}/.vpsguard-test/systemd/vps-guard-edge.service.active"
printf 'present\n' >"${root}/.vpsguard-test/account-vps-guard"

snapshot_output="$(
  VPS_GUARD_TEST_ROOT="${root}" \
  VPS_GUARD_SNAPSHOT_ROOT="${snapshots}" \
    bash "${repo_root}/scripts/deployment-state.sh" --snapshot
)"
snapshot="${snapshot_output#snapshot=}"
[[ -d "${snapshot}" && -f "${snapshot}/SHA256SUMS" ]]
if grep -Rqs 'fixture-old-token' "${snapshot}"/manifest.* "${snapshot}"/*.txt 2>/dev/null; then
  echo "snapshot metadata exposed a token" >&2
  exit 1
fi

printf 'new-binary\n' >"${root}/usr/local/bin/vps-guard"
printf 'new-control\n' >"${root}/usr/local/bin/vps-guard-control"
printf 'new-config\n' >"${root}/etc/vps-guard/config.toml"
printf 'fixture-new-token\n' >"${root}/etc/vps-guard/secrets/cloudflare-token"
mkdir -p "${root}/etc/systemd/system"
printf 'new-unit\n' >"${root}/etc/systemd/system/vps-guard-edge.service"
printf 'disabled\n' >"${root}/.vpsguard-test/systemd/vps-guard-control.service.enabled"
printf 'inactive\n' >"${root}/.vpsguard-test/systemd/vps-guard-control.service.active"
printf 'enabled\n' >"${root}/.vpsguard-test/systemd/vps-guard-edge.service.enabled"
printf 'active\n' >"${root}/.vpsguard-test/systemd/vps-guard-edge.service.active"

restore_output="$(
  VPS_GUARD_TEST_ROOT="${root}" \
  VPS_GUARD_SNAPSHOT_ROOT="${snapshots}" \
  VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
    bash "${repo_root}/scripts/deployment-state.sh" --restore "${snapshot}"
)"
grep -Fq 'restore=pass' <<<"${restore_output}"
grep -Fxq 'old-binary' "${root}/usr/local/bin/vps-guard"
grep -Fxq 'old-config' "${root}/etc/vps-guard/config.toml"
grep -Fxq 'fixture-old-token' "${root}/etc/vps-guard/secrets/cloudflare-token"
[[ "$(file_mode "${root}/etc/vps-guard/secrets/cloudflare-token")" == 600 ]]
[[ ! -e "${root}/usr/local/bin/vps-guard-control" ]]
[[ ! -e "${root}/etc/systemd/system/vps-guard-edge.service" ]]
grep -Fxq 'enabled' "${root}/.vpsguard-test/systemd/vps-guard-control.service.enabled"
grep -Fxq 'active' "${root}/.vpsguard-test/systemd/vps-guard-control.service.active"
grep -Fxq 'disabled' "${root}/.vpsguard-test/systemd/vps-guard-edge.service.enabled"
grep -Fxq 'inactive' "${root}/.vpsguard-test/systemd/vps-guard-edge.service.active"

verify_output="$(
  VPS_GUARD_TEST_ROOT="${root}" \
  VPS_GUARD_SNAPSHOT_ROOT="${snapshots}" \
    bash "${repo_root}/scripts/deployment-state.sh" --verify "${snapshot}"
)"
grep -Fq 'protected=pass' <<<"${verify_output}"

printf 'nginx-drift\n' >"${root}/etc/nginx/sites-enabled/g7.conf"
if VPS_GUARD_TEST_ROOT="${root}" VPS_GUARD_SNAPSHOT_ROOT="${snapshots}" \
  bash "${repo_root}/scripts/deployment-state.sh" --verify "${snapshot}" >/dev/null 2>&1; then
  echo "protected Nginx drift was accepted" >&2
  exit 1
fi
printf 'nginx-original\n' >"${root}/etc/nginx/sites-enabled/g7.conf"

payload_file="$(find "${snapshot}/payload" -type f | head -1)"
printf 'corrupt\n' >>"${payload_file}"
if VPS_GUARD_TEST_ROOT="${root}" VPS_GUARD_SNAPSHOT_ROOT="${snapshots}" \
  VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
  bash "${repo_root}/scripts/deployment-state.sh" --restore "${snapshot}" >/dev/null 2>&1; then
  echo "corrupt snapshot was restored" >&2
  exit 1
fi

echo "deployment restore harness: PASS"
