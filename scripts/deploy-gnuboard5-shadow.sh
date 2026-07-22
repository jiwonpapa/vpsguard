#!/usr/bin/env bash
# OPS-001/OPS-009/OPS-011: checksum-verified G5 lab shadow install after typed snapshot.
set -euo pipefail
bundle="${1:?bundle path is required}"
snapshot="${2:?deployment snapshot is required}"
[[ "${bundle}" =~ ^/home/gnuboard5/vpsguard-lab-bundle-[0-9]+$ ]]
[[ "${snapshot}" =~ ^/var/backups/vps-guard/deployments/deploy-[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]]
test -d "${bundle}" && test ! -L "${bundle}"
(cd "${bundle}" && sha256sum --check SHA256SUMS >/dev/null)

restore_on_error() {
  local rc=$?
  trap - EXIT
  if [[ ${rc} -ne 0 ]]; then
    VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
      "${bundle}/bin/vps-guard" ops deployment-state restore "${snapshot}" || true
  fi
  exit "${rc}"
}
trap restore_on_error EXIT

id -u vps-guard >/dev/null 2>&1 || \
  useradd --system --home /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard
install -d -m 0750 -o root -g vps-guard /etc/vps-guard
install -d -m 0750 -o vps-guard -g vps-guard /var/lib/vps-guard /var/lib/vps-guard/events
install -m 0755 -o root -g root "${bundle}/bin/vps-guard" /usr/local/bin/vps-guard
install -m 0755 -o root -g root "${bundle}/bin/vps-guard-control" /usr/local/bin/vps-guard-control
install -m 0755 -o root -g root "${bundle}/bin/vps-guard-edge" /usr/local/bin/vps-guard-edge
install -m 0644 -o root -g root "${bundle}/systemd/vps-guard-control.service" /etc/systemd/system/vps-guard-control.service
install -m 0644 -o root -g root "${bundle}/systemd/vps-guard-edge.service" /etc/systemd/system/vps-guard-edge.service
install -m 0640 -o root -g vps-guard "${bundle}/gnuboard5/vps-guard.observe.toml" /etc/vps-guard/config.toml
install -m 0644 -o root -g root "${bundle}/gnuboard5/rootCA.pem" /etc/vps-guard/gnuboard5-lab-rootCA.pem
systemctl daemon-reload
systemctl enable --now vps-guard-control.service vps-guard-edge.service
curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 \
  -H 'Host: gnuboard5.local' http://127.0.0.1:18080/health/live >/dev/null
systemctl is-active --quiet apache2.service
echo "gnuboard5 shadow install: PASS"
