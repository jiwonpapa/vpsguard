#!/usr/bin/env bash
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
  [[ ${rc} -eq 0 ]] || VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot \
    "${bundle}/bin/vps-guard" ops deployment-state restore "${snapshot}" || true
  exit "${rc}"
}
trap restore_on_error EXIT
id -u vps-guard >/dev/null 2>&1 || \
  useradd --system --home /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard
getent group vpsguard-admin >/dev/null
id -nG gnuboard5 | tr ' ' '\n' | grep -Fxq vpsguard-admin
install -d -m 0750 -o root -g vps-guard /etc/vps-guard
install -d -m 0750 -o vps-guard -g vps-guard /var/lib/vps-guard /var/lib/vps-guard/events
install -m 0755 -o root -g root "${bundle}"/bin/vps-guard{,-control,-privileged,-edge} /usr/local/bin/
install -m 0644 -o root -g root "${bundle}"/systemd/{vps-guard-control.service,vps-guard-privileged.service,vps-guard-privileged.socket,vps-guard-edge.service} /etc/systemd/system/
install -m 0644 -o root -g root "${bundle}/tmpfiles/vps-guard.conf" /usr/lib/tmpfiles.d/vps-guard.conf
install -m 0644 -o root -g root "${bundle}/pam/vps-guard" /etc/pam.d/vps-guard
install -m 0640 -o root -g vps-guard "${bundle}/gnuboard5/vps-guard.observe.toml" /etc/vps-guard/config.toml
install -m 0644 -o root -g root "${bundle}/gnuboard5/crawler-networks.json" /etc/vps-guard/crawler-networks.json
test ! -f "${bundle}/gnuboard5/rootCA.pem" || install -m 0644 -o root -g root "${bundle}/gnuboard5/rootCA.pem" /etc/vps-guard/gnuboard5-lab-rootCA.pem
install -d -m 0755 -o root -g root /etc/vps-guard/apache
install -m 0644 -o root -g root "${bundle}/gnuboard5/apache/waf-detection.conf" /etc/vps-guard/apache/waf-active.conf
install -m 0644 -o root -g root "${bundle}/gnuboard5/apache/gnuboard5-crs-exclusions.conf" /etc/vps-guard/apache/gnuboard5-crs-exclusions.conf
systemctl daemon-reload
systemd-tmpfiles --create /usr/lib/tmpfiles.d/vps-guard.conf
systemctl enable vps-guard-privileged.socket vps-guard-privileged.service vps-guard-control.service vps-guard-edge.service
systemctl restart vps-guard-privileged.socket vps-guard-privileged.service vps-guard-control.service vps-guard-edge.service
curl --fail --silent --show-error --retry 20 --retry-connrefused --retry-delay 0 -H 'Host: gnuboard5.local' http://127.0.0.1:18080/health/live >/dev/null
systemctl is-active --quiet apache2.service
echo "gnuboard5 shadow install: PASS"
