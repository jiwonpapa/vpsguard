#!/usr/bin/env bash
set -euo pipefail

# OPS-002, OPS-003, OPS-004, TLS-005, ACT-010: g7devops의 public Nginx TLS
# terminator 뒤에 loopback edge와 loopback Nginx origin을 원자적으로 편입합니다.
mode="${1:---preflight}"
direction="${2:---to-edge}"
stage="${3:-}"
active_nginx="/etc/nginx/sites-available/g7.conf"
enabled_nginx="/etc/nginx/sites-enabled/g7.conf"
active_config="/etc/vps-guard/config.toml"
candidate_root="/etc/vps-guard/nginx"
edge_candidate="${candidate_root}/edge-origin.conf"
bypass_candidate="${candidate_root}/public-bypass.conf"
probe_url="https://www.g7devops.com/"
expected_commit="${VPS_GUARD_RELEASE_COMMIT:-}"
headers=""
nginx_test_config=""

usage() {
  echo "usage: $0 [--preflight|--apply] [--to-edge|--to-nginx] STAGE"
}

[[ "${mode}" == "--preflight" || "${mode}" == "--apply" ]] || { usage >&2; exit 2; }
[[ "${direction}" == "--to-edge" || "${direction}" == "--to-nginx" ]] || { usage >&2; exit 2; }
[[ "${stage}" =~ ^/tmp/vpsguard-cutover\.[A-Za-z0-9]+$ ]] || {
  echo "invalid cutover staging path" >&2
  exit 2
}
[[ "${EUID}" -eq 0 ]] || { echo "root is required for cutover" >&2; exit 2; }
[[ "${expected_commit}" =~ ^[0-9a-f]{40}$ ]] || { echo "release commit is required" >&2; exit 2; }

for required in \
  BUILD-INFO.txt \
  SHA256SUMS \
  ingress-transaction.sh \
  operation-lock.sh \
  vps-guard.shadow.toml \
  vps-guard.ingress.toml \
  g7devops-edge.conf \
  g7devops-bypass.conf; do
  [[ -f "${stage}/${required}" && ! -L "${stage}/${required}" ]] || {
    echo "cutover staging file missing: ${required}" >&2
    exit 2
  }
done
# shellcheck source=operation-lock.sh
source "${stage}/operation-lock.sh"

release_commit="$(tail -1 "${stage}/BUILD-INFO.txt")"
[[ "${release_commit}" == "${expected_commit}" ]] || {
  echo "staged release commit does not match confirmation" >&2
  exit 2
}
grep -Fxq 'target=x86_64-unknown-linux-gnu' "${stage}/BUILD-INFO.txt"

for binary in vps-guard vps-guard-control vps-guard-edge; do
  expected_hash="$(awk -v path="./bin/${binary}" '$2 == path { print $1 }' "${stage}/SHA256SUMS")"
  [[ "${expected_hash}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "release hash missing for ${binary}" >&2
    exit 2
  }
  actual_hash="$(sha256sum "/usr/local/bin/${binary}" | awk '{print $1}')"
  [[ "${actual_hash}" == "${expected_hash}" ]] || {
    echo "installed binary does not match release: ${binary}" >&2
    exit 1
  }
done

systemctl is-active --quiet nginx.service
systemctl is-active --quiet php8.5-fpm.service
systemctl is-active --quiet mysql.service
systemctl is-active --quiet redis-server.service
systemctl is-active --quiet g7-queue.service
systemctl is-active --quiet g7-reverb.service
systemctl is-active --quiet vps-guard-control.service
systemctl is-active --quiet vps-guard-edge.service || [[ "${direction}" == "--to-edge" ]]
[[ -L "${enabled_nginx}" && "$(readlink -f "${enabled_nginx}")" == "${active_nginx}" ]]
[[ -f "${active_nginx}" && ! -L "${active_nginx}" ]]
[[ -f "${active_config}" && ! -L "${active_config}" ]]
nginx -V 2>&1 | grep -Fq -- '--with-http_realip_module'
nginx -t >/dev/null
/usr/local/bin/vps-guard check-config --config "${stage}/vps-guard.ingress.toml" >/dev/null

nginx_test_config="$(mktemp /etc/nginx/vpsguard-test.XXXXXX.conf)"
awk -v candidate="${stage}/g7devops-edge.conf" '
  $1 == "include" && $2 == "/etc/nginx/sites-enabled/*;" {
    print "\tinclude " candidate ";"
    replaced = 1
    next
  }
  { print }
  END { exit replaced ? 0 : 1 }
' /etc/nginx/nginx.conf >"${nginx_test_config}"
grep -Fq "include ${stage}/g7devops-edge.conf;" "${nginx_test_config}"
nginx -t -p /etc/nginx/ -c "${nginx_test_config}" >/dev/null
rm -f "${nginx_test_config}"
nginx_test_config=""

if ! cmp -s "${active_nginx}" "${stage}/g7devops-bypass.conf" && \
   ! cmp -s "${active_nginx}" "${stage}/g7devops-edge.conf"; then
  echo "active g7 Nginx config is not an approved cutover candidate" >&2
  exit 1
fi
if ! cmp -s "${active_config}" "${stage}/vps-guard.shadow.toml" && \
   ! cmp -s "${active_config}" "${stage}/vps-guard.ingress.toml"; then
  echo "active VPSGuard config is not an approved cutover candidate" >&2
  exit 1
fi

public_status="$(curl --fail --silent --show-error --max-time 10 \
  --output /dev/null --write-out '%{http_code}' "${probe_url}")"
[[ "${public_status}" == "200" ]]
echo "g7devops ingress preflight: PASS"
echo "topology=public-nginx-tls->127.0.0.1:18080->127.0.0.1:18081->php-fpm"

if [[ "${mode}" == "--preflight" ]]; then
  exit 0
fi

[[ "${VPS_GUARD_CUTOVER_CONFIRM:-}" == "g7devops:${direction#--}:${expected_commit}" ]] || {
  echo "VPS_GUARD_CUTOVER_CONFIRM=g7devops:${direction#--}:${expected_commit} is required" >&2
  exit 2
}
operation_lock_acquire "ingress-${direction#--}-$$"
operation_progress preflight completed

snapshot_output="$(/usr/local/libexec/vps-guard/deployment-state --snapshot)"
snapshot="${snapshot_output#snapshot=}"
[[ "${snapshot}" =~ ^/var/backups/vps-guard/deployments/deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
  echo "pre-cutover deployment snapshot was not created" >&2
  exit 1
}

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/lib/vps-guard/backups/cutover-${timestamp}"
install -d -m 0750 "${backup}"
install -m 0644 "${active_nginx}" "${backup}/g7.conf"
install -m 0640 "${active_config}" "${backup}/config.toml"
edge_was_active=false
if systemctl is-active --quiet vps-guard-edge.service; then
  edge_was_active=true
fi

rollback() {
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    return
  fi
  trap - EXIT
  [[ -z "${headers}" ]] || rm -f "${headers}"
  [[ -z "${nginx_test_config}" ]] || rm -f "${nginx_test_config}"
  echo "g7devops cutover failed; restoring active Nginx and VPSGuard config" >&2
  operation_progress rollback started
  install -m 0644 -o root -g root "${backup}/g7.conf" "${active_nginx}"
  install -m 0640 -o root -g vps-guard "${backup}/config.toml" "${active_config}"
  /usr/local/bin/vps-guard check-config --config "${active_config}" || true
  nginx -t || true
  systemctl reload nginx.service || true
  if [[ "${edge_was_active}" == true ]]; then
    systemctl restart vps-guard-edge.service || true
  else
    systemctl stop vps-guard-edge.service || true
  fi
  operation_progress rollback completed
  operation_lock_release
  echo "rollback snapshot=$(basename "${snapshot}")" >&2
  exit "${rc}"
}
trap rollback EXIT

install -d -m 0750 -o root -g vps-guard "${candidate_root}"
install -m 0640 -o root -g vps-guard "${stage}/g7devops-edge.conf" "${edge_candidate}"
install -m 0640 -o root -g vps-guard "${stage}/g7devops-bypass.conf" "${bypass_candidate}"

if [[ "${direction}" == "--to-edge" ]]; then
  install -m 0640 -o root -g vps-guard \
    "${stage}/vps-guard.ingress.toml" "${active_config}"
  /usr/local/bin/vps-guard check-config --config "${active_config}" >/dev/null
  systemctl restart vps-guard-edge.service
  curl --fail --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
    -H 'Host: www.g7devops.com' \
    http://127.0.0.1:18080/health/live >/dev/null
fi

VPS_GUARD_NGINX_ACTIVE="${active_nginx}" \
VPS_GUARD_NGINX_EDGE_CANDIDATE="${edge_candidate}" \
VPS_GUARD_NGINX_BYPASS_CANDIDATE="${bypass_candidate}" \
VPS_GUARD_INGRESS_CONFIRM="${direction#--}" \
VPS_GUARD_INGRESS_PROBE_URL="${probe_url}" \
  bash "${stage}/ingress-transaction.sh" "${direction}" --apply

headers="$(mktemp)"
curl --fail --silent --show-error --max-time 10 \
  --resolve www.g7devops.com:443:127.0.0.1 \
  --dump-header "${headers}" --output /dev/null "${probe_url}"

if [[ "${direction}" == "--to-edge" ]]; then
  grep -Eiq '^x-vps-guard:[[:space:]]*guard-edge' "${headers}"
  curl --fail --silent --show-error --max-time 5 \
    -H 'Host: www.g7devops.com' http://127.0.0.1:18080/health/ready >/dev/null
  systemctl is-active --quiet vps-guard-edge.service
  ss -H -ltn | awk '{print $4}' | grep -Fxq '127.0.0.1:18081'
else
  if grep -Eiq '^x-vps-guard:' "${headers}"; then
    echo "bypass response still traverses VPSGuard" >&2
    exit 1
  fi
  if systemctl is-active --quiet vps-guard-edge.service; then
    echo "VPSGuard edge is still active after bypass" >&2
    exit 1
  fi
  if ss -H -ltn | awk '{print $4}' | grep -Fxq '127.0.0.1:18081'; then
    echo "loopback Nginx origin is still active after bypass" >&2
    exit 1
  fi
fi

rm -f "${headers}"
headers=""
nginx -t >/dev/null
systemctl is-active --quiet nginx.service
operation_progress verify completed
operation_lock_release
trap - EXIT
echo "g7devops ingress transaction: PASS"
echo "direction=${direction#--}"
echo "backup=${backup}"
echo "snapshot=$(basename "${snapshot}")"
