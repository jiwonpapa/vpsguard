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

systemctl disable --now vps-guard-edge.service vps-guard-control.service || true
if /usr/sbin/nft list table inet vps_guard >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet vps_guard
fi
while IFS= read -r path; do
  case "${path}" in
    /usr/local/bin/vps-guard|/usr/local/bin/vps-guard-control|/usr/local/bin/vps-guard-edge|/etc/systemd/system/vps-guard-control.service|/etc/systemd/system/vps-guard-edge.service|/usr/lib/tmpfiles.d/vps-guard.conf)
      rm -f "${path}"
      ;;
    "") ;;
    *) echo "foreign manifest path rejected: ${path}" >&2; exit 2 ;;
  esac
done <"${manifest}"
systemctl daemon-reload
echo "uninstall complete; configuration, state, certificates and site data were preserved"
