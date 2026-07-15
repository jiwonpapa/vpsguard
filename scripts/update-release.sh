#!/usr/bin/env bash
set -euo pipefail

# OPS-005, OPS-009: 검증된 bundle만 설치하고 실패하면 배포 snapshot으로 복구합니다.
mode="${1:---plan}"
bundle="${2:-}"
manifest_name="ownership-manifest.txt"
health_url="${VPS_GUARD_CONTROL_HEALTH_URL:-http://127.0.0.1:7727/health/live}"
edge_health_url="${VPS_GUARD_EDGE_HEALTH_URL:-http://127.0.0.1:18080/health/live}"
edge_host="${VPS_GUARD_EDGE_HOST:-}"
snapshot=""

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
[[ "${EUID}" -eq 0 ]] || { echo "root is required for update" >&2; exit 2; }
[[ -d "${bundle}" ]] || { echo "bundle directory is required" >&2; exit 2; }
[[ -n "${edge_host}" ]] || { echo "VPS_GUARD_EDGE_HOST is required" >&2; exit 2; }
[[ "${edge_host}" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "invalid edge Host" >&2; exit 2; }
(cd "${bundle}" && sha256sum --check SHA256SUMS)
for binary in vps-guard vps-guard-control vps-guard-edge; do
  [[ -x "${bundle}/bin/${binary}" ]]
done
for required in \
  "${bundle}/systemd/vps-guard-control.service" \
  "${bundle}/systemd/vps-guard-edge.service" \
  "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf" \
  "${bundle}/tmpfiles/vps-guard.conf" \
  "${bundle}/scripts/deployment-state.sh" \
  "${bundle}/${manifest_name}"; do
  [[ -f "${required}" ]] || { echo "bundle file missing: ${required}" >&2; exit 2; }
done

snapshot_output="$(bash "${bundle}/scripts/deployment-state.sh" --snapshot)"
snapshot="${snapshot_output#snapshot=}"
[[ "${snapshot}" =~ ^/var/backups/vps-guard/deployments/deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || {
  echo "deployment snapshot was not created" >&2
  exit 1
}

rollback() {
  local rc=$?
  if [[ ${rc} -eq 0 ]]; then
    return
  fi
  echo "update failed; restoring deployment snapshot" >&2
  VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
    bash "${bundle}/scripts/deployment-state.sh" --restore "${snapshot}" || \
    echo "automatic update restore failed; snapshot=${snapshot}" >&2
  exit "${rc}"
}
trap rollback EXIT

install -m 0755 "${bundle}/bin/vps-guard" /usr/local/bin/vps-guard
install -m 0755 "${bundle}/bin/vps-guard-control" /usr/local/bin/vps-guard-control
install -m 0755 "${bundle}/bin/vps-guard-edge" /usr/local/bin/vps-guard-edge
install -d -m 0755 /usr/local/libexec/vps-guard
install -m 0755 "${bundle}/scripts/deployment-state.sh" /usr/local/libexec/vps-guard/deployment-state
install -m 0644 "${bundle}/systemd/vps-guard-control.service" /etc/systemd/system/vps-guard-control.service
install -m 0644 "${bundle}/systemd/vps-guard-edge.service" /etc/systemd/system/vps-guard-edge.service
if [[ -f /etc/vps-guard/secrets/cloudflare-token ]]; then
  install -d -m 0755 /etc/systemd/system/vps-guard-control.service.d
  install -m 0644 \
    "${bundle}/systemd/vps-guard-control.service.d/20-cloudflare-credential.conf" \
    /etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf
fi
install -m 0644 "${bundle}/tmpfiles/vps-guard.conf" /usr/lib/tmpfiles.d/vps-guard.conf
install -d -m 0750 /var/lib/vps-guard
install -m 0644 "${bundle}/${manifest_name}" /var/lib/vps-guard/ownership-manifest.txt
systemctl daemon-reload
/usr/local/bin/vps-guard check-config --config /etc/vps-guard/config.toml
systemctl restart vps-guard-control.service vps-guard-edge.service
curl --fail --silent "${health_url}" >/dev/null
curl --fail --silent -H "Host: ${edge_host}" "${edge_health_url}" >/dev/null
bash "${bundle}/scripts/deployment-state.sh" --verify "${snapshot}" >/dev/null
trap - EXIT
echo "update complete; snapshot=${snapshot}"
