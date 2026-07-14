#!/usr/bin/env bash
set -euo pipefail

direction="${1:---plan}"
mode="${2:---plan}"
active_config="${VPS_GUARD_NGINX_ACTIVE:-/etc/nginx/conf.d/vps-guard-ingress.conf}"
edge_candidate="${VPS_GUARD_NGINX_EDGE_CANDIDATE:-/etc/vps-guard/nginx/edge-origin.conf}"
bypass_candidate="${VPS_GUARD_NGINX_BYPASS_CANDIDATE:-/etc/vps-guard/nginx/public-bypass.conf}"
probe_url="${VPS_GUARD_INGRESS_PROBE_URL:-}"
backup_root="/var/lib/vps-guard/backups"

case "${direction}" in
  --to-edge) candidate="${edge_candidate}" ;;
  --to-nginx) candidate="${bypass_candidate}" ;;
  --plan)
    echo "usage: $0 [--to-edge|--to-nginx] [--plan|--apply]"
    echo "preserve: SSH, certificates, site data, VPSGuard config/state"
    exit 0
    ;;
  *) echo "unknown direction: ${direction}" >&2; exit 2 ;;
esac

echo "direction: ${direction}"
echo "mode: ${mode}"
echo "candidate: ${candidate}"
echo "active nginx include: ${active_config}"
echo "preserve: SSH, certificates, site data, VPSGuard config/state"

[[ "${candidate}" == /etc/vps-guard/nginx/* ]] || {
  echo "candidate must be under /etc/vps-guard/nginx" >&2
  exit 2
}
[[ "${active_config}" == /etc/nginx/* ]] || {
  echo "active config must be under /etc/nginx" >&2
  exit 2
}
if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { echo "expected --plan or --apply" >&2; exit 2; }
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
backup="${backup_root}/ingress-${timestamp}"
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
