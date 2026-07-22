#!/usr/bin/env bash
set -euo pipefail

mode="${1:---plan}"
manifest="${2:-/var/lib/vps-guard/ownership-manifest.txt}"
repo_manifest="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/packaging/ownership-manifest.txt"

[[ -f "${manifest}" ]] || manifest="${repo_manifest}"
echo "mode: ${mode}"
echo "ownership manifest: ${manifest}"
echo "preserve: /etc/vps-guard, /var/lib/vps-guard, /etc/letsencrypt, Nginx, site data, SSH"
echo "remove owned nft table: inet vps_guard (when present)"
while IFS= read -r path; do
  [[ -z "${path}" ]] || echo "remove owned path: ${path}"
done <"${manifest}"
if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { echo "usage: $0 [--plan|--apply] [manifest]" >&2; exit 2; }
[[ "${VPS_GUARD_UNINSTALL_CONFIRM:-}" == "remove-owned-artifacts-only" ]] || {
  echo "VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only is required" >&2
  exit 2
}
[[ "${VPS_GUARD_BYPASS_VERIFIED:-}" == "nginx-public" ]] || {
  echo "VPS_GUARD_BYPASS_VERIFIED=nginx-public is required" >&2
  exit 2
}
probe_url="${VPS_GUARD_UNINSTALL_PROBE_URL:-}"
[[ -n "${probe_url}" ]] || { echo "VPS_GUARD_UNINSTALL_PROBE_URL is required" >&2; exit 2; }
nginx -t
systemctl is-active --quiet nginx.service
curl --fail --silent --show-error "${probe_url}" >/dev/null

systemctl stop vps-guard-edge.service
if ! curl --fail --silent --show-error --retry 5 --retry-delay 1 "${probe_url}" >/dev/null; then
  systemctl start vps-guard-edge.service || true
  echo "public Nginx probe failed after edge stop; uninstall aborted and edge restarted" >&2
  exit 1
fi
systemctl disable vps-guard-edge.service
systemctl disable --now vps-guard-control.service || true
if /usr/sbin/nft list table inet vps_guard >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet vps_guard
fi
while IFS= read -r path; do
  case "${path}" in
    /usr/local/bin/vps-guard|/usr/local/bin/vps-guard-control|/usr/local/bin/vps-guard-edge|/usr/local/lib/vps-guard/current|/usr/local/libexec/vps-guard/deployment-state|/usr/local/libexec/vps-guard/state-common.sh|/etc/systemd/system/vps-guard-control.service|/etc/systemd/system/vps-guard-edge.service|/etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf|/etc/systemd/system/vps-guard-control.service.d/20-service-credentials.conf|/etc/systemd/system/vps-guard-control.service.d/30-tls-certificate.conf|/etc/systemd/system/vps-guard-edge.service.d/30-tls-credentials.conf|/usr/lib/tmpfiles.d/vps-guard.conf)
      rm -f "${path}"
      ;;
    /usr/local/lib/vps-guard/releases)
      rm -rf "${path}"
      ;;
    "") ;;
    *) echo "foreign manifest path rejected: ${path}" >&2; exit 2 ;;
  esac
done <"${manifest}"
rmdir /usr/local/libexec/vps-guard 2>/dev/null || true
rmdir /usr/local/lib/vps-guard 2>/dev/null || true
rmdir /etc/systemd/system/vps-guard-control.service.d 2>/dev/null || true
rmdir /etc/systemd/system/vps-guard-edge.service.d 2>/dev/null || true
systemctl daemon-reload
echo "uninstall complete; configuration, state, certificates and site data were preserved"
