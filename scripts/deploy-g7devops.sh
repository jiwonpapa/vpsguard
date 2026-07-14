#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:---plan}"
bundle="${2:-${repo_root}/target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-0.1.0}"
remote_stage="/tmp/vpsguard-shadow-deploy"

echo "target: ssh g7devops"
echo "mode: shadow deployment only"
echo "bundle: ${bundle}"
echo "preserve: SSH, Nginx public 80/443, certificates, site data"
echo "remote config: /etc/vps-guard/config.toml must already exist and use non-public shadow ports"

if [[ "${mode}" == "--plan" ]]; then
  exit 0
fi
if [[ "${mode}" != "--apply" ]]; then
  echo "usage: $0 [--plan|--apply] [bundle-directory]" >&2
  exit 2
fi
if [[ "${VPS_GUARD_DEPLOY_CONFIRM:-}" != "g7devops-shadow" ]]; then
  echo "VPS_GUARD_DEPLOY_CONFIRM=g7devops-shadow is required" >&2
  exit 2
fi
for binary in vps-guard vps-guard-control vps-guard-edge; do
  test -x "${bundle}/bin/${binary}"
done

ssh g7devops "rm -rf '${remote_stage}' && mkdir -p '${remote_stage}'"
scp -r "${bundle}/bin" "${bundle}/systemd" "${bundle}/tmpfiles" g7devops:"${remote_stage}/"
ssh g7devops "test -f /etc/vps-guard/config.toml && grep -Eq '^http_bind = \"127\\.0\\.0\\.1:' /etc/vps-guard/config.toml"
ssh g7devops "sudo id -u vps-guard >/dev/null 2>&1 || sudo useradd --system --home /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard"
ssh g7devops "sudo install -m 0755 '${remote_stage}'/bin/* /usr/local/bin/ && sudo install -m 0644 '${remote_stage}'/systemd/* /etc/systemd/system/ && sudo install -m 0644 '${remote_stage}'/tmpfiles/vps-guard.conf /usr/lib/tmpfiles.d/ && sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/vps-guard.conf && sudo systemctl daemon-reload"
ssh g7devops "sudo /usr/local/bin/vps-guard check-config --config /etc/vps-guard/config.toml"
ssh g7devops "sudo systemctl enable --now vps-guard-control.service vps-guard-edge.service"
ssh g7devops "curl --fail --silent http://127.0.0.1:7727/health/live && sudo systemctl --no-pager --full status vps-guard-control.service vps-guard-edge.service"

echo "shadow deployment complete; public 80/443 and Nginx were not changed"
