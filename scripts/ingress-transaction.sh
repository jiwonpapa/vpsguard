#!/usr/bin/env bash
set -euo pipefail

direction="${1:---plan}"
mode="${2:---plan}"
test_root="${VPS_GUARD_TEST_ROOT:-}"
active_config_logical="${VPS_GUARD_NGINX_ACTIVE:-/etc/nginx/conf.d/vps-guard-ingress.conf}"
edge_candidate_logical="${VPS_GUARD_NGINX_EDGE_CANDIDATE:-/etc/vps-guard/nginx/edge-origin.conf}"
bypass_candidate_logical="${VPS_GUARD_NGINX_BYPASS_CANDIDATE:-/etc/vps-guard/nginx/public-bypass.conf}"
probe_url="${VPS_GUARD_INGRESS_PROBE_URL:-}"

root_path() {
  printf '%s%s' "${test_root}" "$1"
}

[[ -z "${test_root}" || "${test_root}" == /* ]] || {
  echo "VPS_GUARD_TEST_ROOT must be absolute" >&2
  exit 2
}
active_config="$(root_path "${active_config_logical}")"
edge_candidate="$(root_path "${edge_candidate_logical}")"
bypass_candidate="$(root_path "${bypass_candidate_logical}")"
backup_root="${VPS_GUARD_BACKUP_ROOT:-$(root_path /var/lib/vps-guard/backups)}"

case "${direction}" in
  --to-edge)
    candidate="${edge_candidate}"
    candidate_logical="${edge_candidate_logical}"
    ;;
  --to-nginx)
    candidate="${bypass_candidate}"
    candidate_logical="${bypass_candidate_logical}"
    ;;
  --plan)
    echo "usage: $0 [--to-edge|--to-nginx] [--plan|--apply]"
    echo "preserve: SSH, certificates, site data, VPSGuard config/state"
    exit 0
    ;;
  *) echo "unknown direction: ${direction}" >&2; exit 2 ;;
esac

echo "direction: ${direction}"
echo "mode: ${mode}"
echo "candidate: ${candidate_logical}"
echo "active nginx include: ${active_config_logical}"
echo "preserve: SSH, certificates, site data, VPSGuard config/state"

[[ "${candidate_logical}" == /etc/vps-guard/nginx/* ]] || {
  echo "candidate must be under /etc/vps-guard/nginx" >&2
  exit 2
}
[[ "${active_config_logical}" == /etc/nginx/* ]] || {
  echo "active config must be under /etc/nginx" >&2
  exit 2
}
if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { echo "expected --plan or --apply" >&2; exit 2; }
[[ -n "${test_root}" || "${EUID}" -eq 0 ]] || { echo "root is required for ingress apply" >&2; exit 2; }
[[ "${VPS_GUARD_INGRESS_CONFIRM:-}" == "${direction#--}" ]] || {
  echo "VPS_GUARD_INGRESS_CONFIRM=${direction#--} is required" >&2
  exit 2
}
[[ -n "${probe_url}" ]] || { echo "VPS_GUARD_INGRESS_PROBE_URL is required" >&2; exit 2; }
[[ -f "${candidate}" ]] || { echo "candidate not found: ${candidate}" >&2; exit 2; }

edge_was_active=false
if systemctl is-active --quiet vps-guard-edge.service; then
  edge_was_active=true
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${backup_root}/ingress-${timestamp}-$$"
install -d -m 0750 "${backup}"
had_active=false
if [[ -f "${active_config}" ]]; then
  had_active=true
  install -m 0644 "${active_config}" "${backup}/active.conf"
fi

rollback() {
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    return
  fi
  echo "ingress transaction failed; restoring snapshot" >&2
  if [[ "${had_active}" == true ]]; then
    install -m 0644 "${backup}/active.conf" "${active_config}"
  else
    rm -f "${active_config}"
  fi
  nginx -t || true
  systemctl reload nginx.service || true
  if [[ "${edge_was_active}" == true ]]; then
    systemctl start vps-guard-edge.service || true
  else
    systemctl stop vps-guard-edge.service || true
  fi
  exit "${rc}"
}
trap rollback EXIT

install -m 0644 "${candidate}" "${active_config}"
nginx -t
if [[ "${direction}" == "--to-nginx" ]]; then
  systemctl stop vps-guard-edge.service
  systemctl reload nginx.service
else
  systemctl reload nginx.service
  systemctl start vps-guard-edge.service
fi
curl --fail --silent --show-error --retry 10 --retry-delay 1 "${probe_url}" >/dev/null
trap - EXIT
echo "ingress transaction complete: ${direction}"
