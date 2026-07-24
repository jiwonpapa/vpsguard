#!/usr/bin/env bash
set -euo pipefail
mode="${1:---plan}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=state-common.sh
source "${script_dir}/state-common.sh"; require_fixture_root
manifest="${2:-$(root_path /var/lib/vps-guard/ownership-manifest.txt)}"
repo_manifest="${script_dir}/../packaging/ownership-manifest.txt"
[[ -f "${manifest}" ]] || manifest="${repo_manifest}"
echo "mode: ${mode}"
echo "ownership manifest: ${manifest}"
echo "preserve: /etc/vps-guard, /var/lib/vps-guard, /etc/letsencrypt, ingress config, site data, SSH"
echo "remove owned nft table: inet vps_guard (when present)"
while IFS= read -r path; do
  if [[ "${path}" == "/etc/vps-guard/crawler-networks.json" || "${path}" == "/etc/vps-guard/apache" ]]; then action="preserve configuration"; else action="remove owned"; fi
  [[ -z "${path}" ]] || echo "${action} path: ${path}"
done <"${manifest}"
[[ "${mode}" != "--plan" ]] || exit 0
[[ "${mode}" == "--apply" ]] || { echo "usage: $0 [--plan|--apply] [manifest]" >&2; exit 2; }
[[ -n "${test_root}" || "${EUID}" -eq 0 ]] || { echo "root is required for uninstall" >&2; exit 2; }
[[ "${VPS_GUARD_UNINSTALL_CONFIRM:-}" == "remove-owned-artifacts-only" ]] ||
  { echo "VPS_GUARD_UNINSTALL_CONFIRM=remove-owned-artifacts-only is required" >&2; exit 2; }
ingress="${VPS_GUARD_BYPASS_VERIFIED:-}"; web_service=""
case "${ingress}" in
  nginx-public) web_service="nginx.service"; nginx -t ;;
  apache-public) web_service="apache2.service"; apache2ctl configtest ;;
  *) echo "VPS_GUARD_BYPASS_VERIFIED must be nginx-public or apache-public" >&2; exit 2 ;;
esac
probe_url="${VPS_GUARD_UNINSTALL_PROBE_URL:-}"; [[ -n "${probe_url}" ]] || { echo "VPS_GUARD_UNINSTALL_PROBE_URL is required" >&2; exit 2; }
probe_ca="${VPS_GUARD_UNINSTALL_PROBE_CA:-}"; curl_ca=(); [[ -z "${probe_ca}" ]] || { [[ "${probe_ca}" == /etc/ssl/*.pem && -f "${probe_ca}" ]] || { echo "VPS_GUARD_UNINSTALL_PROBE_CA must be an existing /etc/ssl/*.pem file" >&2; exit 2; }; curl_ca=(--cacert "${probe_ca}"); }
systemctl is-active --quiet "${web_service}"
curl --fail --silent --show-error "${curl_ca[@]}" "${probe_url}" >/dev/null
systemctl stop vps-guard-edge.service
if ! curl --fail --silent --show-error --retry 5 --retry-delay 1 "${curl_ca[@]}" "${probe_url}" >/dev/null; then
  systemctl start vps-guard-edge.service || true
  echo "public ingress probe failed after edge stop; uninstall aborted and edge restarted" >&2
  exit 1
fi
systemctl disable vps-guard-edge.service
systemctl disable --now vps-guard-control.service || true
systemctl disable --now vps-guard-privileged.service vps-guard-privileged.socket || true
if /usr/sbin/nft list table inet vps_guard >/dev/null 2>&1; then /usr/sbin/nft delete table inet vps_guard; fi
while IFS= read -r path; do
  case "${path}" in
    /usr/local/bin/vps-guard|/usr/local/bin/vps-guard-control|/usr/local/bin/vps-guard-privileged|/usr/local/bin/vps-guard-edge|/usr/local/lib/vps-guard/current|/usr/local/libexec/vps-guard/deployment-state|/usr/local/libexec/vps-guard/state-common.sh|/etc/systemd/system/vps-guard-control.service|/etc/systemd/system/vps-guard-privileged.service|/etc/systemd/system/vps-guard-privileged.socket|/etc/systemd/system/vps-guard-edge.service|/etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf|/etc/systemd/system/vps-guard-control.service.d/20-service-credentials.conf|/etc/systemd/system/vps-guard-control.service.d/30-tls-certificate.conf|/etc/systemd/system/vps-guard-edge.service.d/30-tls-credentials.conf|/usr/lib/tmpfiles.d/vps-guard.conf|/etc/pam.d/vps-guard)
      rm -f "$(root_path "${path}")"
      ;;
    /usr/local/lib/vps-guard/releases)
      rm -rf "$(root_path "${path}")"
      ;;
    /etc/vps-guard/crawler-networks.json|/etc/vps-guard/apache)
      echo "preserved configuration path: ${path}"
      ;;
    "") ;;
    *) echo "foreign manifest path rejected: ${path}" >&2; exit 2 ;;
  esac
done <"${manifest}"
rmdir "$(root_path /usr/local/libexec/vps-guard)" 2>/dev/null || true
rmdir "$(root_path /usr/local/lib/vps-guard)" 2>/dev/null || true
rmdir "$(root_path /etc/systemd/system/vps-guard-control.service.d)" 2>/dev/null || true
rmdir "$(root_path /etc/systemd/system/vps-guard-edge.service.d)" 2>/dev/null || true
systemctl daemon-reload; echo "uninstall complete; configuration, state, certificates and site data were preserved"
