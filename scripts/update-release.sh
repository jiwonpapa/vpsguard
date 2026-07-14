#!/usr/bin/env bash
set -euo pipefail

mode="${1:---plan}"
bundle="${2:-}"
manifest_name="ownership-manifest.txt"
health_url="${VPS_GUARD_CONTROL_HEALTH_URL:-http://127.0.0.1:7727/health/live}"
edge_health_url="${VPS_GUARD_EDGE_HEALTH_URL:-http://127.0.0.1:18080/health/live}"
edge_host="${VPS_GUARD_EDGE_HOST:-}"

echo "mode: ${mode}"
echo "bundle: ${bundle:-<required for apply>}"
echo "preserve: /etc/vps-guard, /var/lib/vps-guard, /etc/letsencrypt, Nginx site data"
if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
[[ "${mode}" == "--apply" ]] || { echo "usage: $0 [--plan|--apply] [bundle]" >&2; exit 2; }
[[ "${VPS_GUARD_UPDATE_CONFIRM:-}" == "update-with-rollback" ]] || {
  echo "VPS_GUARD_UPDATE_CONFIRM=update-with-rollback is required" >&2
  exit 2
}
[[ -d "${bundle}" ]] || { echo "bundle directory is required" >&2; exit 2; }
[[ -n "${edge_host}" ]] || { echo "VPS_GUARD_EDGE_HOST is required" >&2; exit 2; }
(cd "${bundle}" && sha256sum --check SHA256SUMS)
for binary in vps-guard vps-guard-control vps-guard-edge; do
  [[ -x "${bundle}/bin/${binary}" ]]
done
[[ -f "${bundle}/${manifest_name}" ]]

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/lib/vps-guard/backups/update-${timestamp}"
install -d -m 0750 "${backup}/bin" "${backup}/systemd" "${backup}/tmpfiles"
absent_paths="${backup}/absent-paths.txt"
: >"${absent_paths}"
for binary in vps-guard vps-guard-control vps-guard-edge; do
  if [[ -f "/usr/local/bin/${binary}" ]]; then
    install -m 0755 "/usr/local/bin/${binary}" "${backup}/bin/"
  else
    echo "/usr/local/bin/${binary}" >>"${absent_paths}"
  fi
done
for unit in vps-guard-control.service vps-guard-edge.service; do
  if [[ -f "/etc/systemd/system/${unit}" ]]; then
    install -m 0644 "/etc/systemd/system/${unit}" "${backup}/systemd/"
  else
    echo "/etc/systemd/system/${unit}" >>"${absent_paths}"
  fi
done
if [[ -f /usr/lib/tmpfiles.d/vps-guard.conf ]]; then
  install -m 0644 /usr/lib/tmpfiles.d/vps-guard.conf "${backup}/tmpfiles/"
else
  echo "/usr/lib/tmpfiles.d/vps-guard.conf" >>"${absent_paths}"
fi
if [[ -f /var/lib/vps-guard/ownership-manifest.txt ]]; then
  install -m 0644 /var/lib/vps-guard/ownership-manifest.txt "${backup}/"
else
  echo "/var/lib/vps-guard/ownership-manifest.txt" >>"${absent_paths}"
fi

rollback() {
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    return
  fi
  echo "update failed; restoring previous owned artifacts" >&2
  install -m 0755 "${backup}"/bin/* /usr/local/bin/ 2>/dev/null || true
  install -m 0644 "${backup}"/systemd/* /etc/systemd/system/ 2>/dev/null || true
  install -m 0644 "${backup}"/tmpfiles/* /usr/lib/tmpfiles.d/ 2>/dev/null || true
  [[ ! -f "${backup}/ownership-manifest.txt" ]] || install -m 0644 "${backup}/ownership-manifest.txt" /var/lib/vps-guard/
  while IFS= read -r path; do
    case "${path}" in
      /usr/local/bin/vps-guard|/usr/local/bin/vps-guard-control|/usr/local/bin/vps-guard-edge|/etc/systemd/system/vps-guard-control.service|/etc/systemd/system/vps-guard-edge.service|/usr/lib/tmpfiles.d/vps-guard.conf|/var/lib/vps-guard/ownership-manifest.txt)
        rm -f "${path}"
        ;;
    esac
  done <"${absent_paths}"
  systemctl daemon-reload || true
  systemctl restart vps-guard-control.service vps-guard-edge.service || true
  exit "${rc}"
}
trap rollback EXIT

install -m 0755 "${bundle}"/bin/* /usr/local/bin/
install -m 0644 "${bundle}"/systemd/* /etc/systemd/system/
install -m 0644 "${bundle}"/tmpfiles/* /usr/lib/tmpfiles.d/
install -d -m 0750 /var/lib/vps-guard
install -m 0644 "${bundle}/${manifest_name}" /var/lib/vps-guard/ownership-manifest.txt
systemctl daemon-reload
/usr/local/bin/vps-guard check-config --config /etc/vps-guard/config.toml
systemctl restart vps-guard-control.service vps-guard-edge.service
curl --fail --silent "${health_url}" >/dev/null
curl --fail --silent -H "Host: ${edge_host}" "${edge_health_url}" >/dev/null
trap - EXIT
echo "update complete; backup=${backup}"
