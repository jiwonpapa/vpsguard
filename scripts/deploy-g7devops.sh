#!/usr/bin/env bash
# shellcheck disable=SC2029 # validated local constants are intentionally expanded for ssh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:---plan}"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
bundle="${2:-${repo_root}/target/release-bundle/x86_64-unknown-linux-gnu/vpsguard-${version}}"
config="${3:-}"
remote_stage="/tmp/vpsguard-shadow-deploy"

echo "target: ssh g7devops"
echo "mode: shadow deployment only"
echo "bundle: ${bundle}"
echo "preserve: SSH, Nginx public 80/443, certificates, site data"
echo "config candidate: ${config:-<required for apply>}"
echo "remote config: an existing file must be byte-identical; this script never overwrites it"

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
[[ -d "${bundle}" && -f "${bundle}/SHA256SUMS" ]] || {
  echo "verified Linux release bundle is required: ${bundle}" >&2
  exit 2
}
[[ -f "${config}" ]] || { echo "shadow config file is required" >&2; exit 2; }
for binary in vps-guard vps-guard-control vps-guard-edge; do
  test -x "${bundle}/bin/${binary}"
done
if command -v sha256sum >/dev/null 2>&1; then
  (cd "${bundle}" && sha256sum --check SHA256SUMS)
else
  (cd "${bundle}" && shasum -a 256 --check SHA256SUMS)
fi
grep -Fxq 'target=x86_64-unknown-linux-gnu' "${bundle}/BUILD-INFO.txt"
grep -Eq '^http_bind = "127\.0\.0\.1:' "${config}"
grep -Eq '^mode = "observe"' "${config}"
grep -Eq '^enabled = false' "${config}"
edge_host="$(sed -n 's/^canonical_host = "\([^"]*\)"/\1/p' "${config}" | head -1)"
[[ -n "${edge_host}" ]] || {
  echo "shadow deploy requires edge.canonical_host for Host-safe smoke" >&2
  exit 2
}
[[ "${edge_host}" =~ ^[A-Za-z0-9.-]+$ ]] || {
  echo "canonical Host contains unsupported characters" >&2
  exit 2
}

ssh g7devops "test \"\$(uname -m)\" = x86_64"

ssh g7devops "rm -rf /tmp/vpsguard-shadow-deploy && mkdir -p /tmp/vpsguard-shadow-deploy"
scp -r "${bundle}" g7devops:"${remote_stage}/bundle"
scp "${config}" g7devops:"${remote_stage}/config.toml"
ssh g7devops "cd ${remote_stage}/bundle && sha256sum --check SHA256SUMS && grep -Fxq 'target=x86_64-unknown-linux-gnu' BUILD-INFO.txt"
ssh g7devops "${remote_stage}/bundle/bin/vps-guard check-config --config ${remote_stage}/config.toml"
ssh g7devops "sudo id -u vps-guard >/dev/null 2>&1 || sudo useradd --system --home /var/lib/vps-guard --shell /usr/sbin/nologin vps-guard"
ssh g7devops "sudo install -d -m 0750 -o root -g vps-guard /etc/vps-guard && if sudo test -f /etc/vps-guard/config.toml; then sudo cmp -s ${remote_stage}/config.toml /etc/vps-guard/config.toml; else sudo install -m 0640 -o root -g vps-guard ${remote_stage}/config.toml /etc/vps-guard/config.toml; fi"
ssh g7devops "sudo env VPS_GUARD_UPDATE_CONFIRM=update-with-rollback VPS_GUARD_EDGE_HOST=${edge_host} bash ${remote_stage}/bundle/scripts/update-release.sh --apply ${remote_stage}/bundle"
ssh g7devops "sudo systemctl enable vps-guard-control.service vps-guard-edge.service && status=\$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: ${edge_host}' http://127.0.0.1:18080/); test \"\${status}\" -lt 500 && curl --fail --silent -H 'Host: ${edge_host}' http://127.0.0.1:18080/health/ready >/dev/null && sudo systemctl --no-pager --full status vps-guard-control.service vps-guard-edge.service"

echo "shadow deployment complete; public 80/443 and Nginx were not changed"
