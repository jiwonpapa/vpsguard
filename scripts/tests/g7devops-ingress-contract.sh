#!/usr/bin/env bash
# shellcheck disable=SC2016 # repository contracts intentionally search literal Nginx variables
set -euo pipefail

# OPS-002, OPS-003, OPS-004, EDGE-003, EDGE-004, TLS-005, ACT-010:
# g7devops 전환 후보가 공개 TLS, 원본 IP와 정확한 bypass 경계를 유지하는지 검사합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

edge="configs/nginx/g7devops-edge.conf"
bypass="configs/nginx/g7devops-bypass.conf"
config="configs/vps-guard.g7devops.ingress.toml"

grep -Fq 'proxy_pass http://127.0.0.1:18080;' "${edge}"
grep -Fq 'listen 127.0.0.1:18081;' "${edge}"
grep -Fq 'fastcgi_pass unix:/run/php/php8.5-fpm-g7devops.sock;' "${edge}"
grep -Fq 'proxy_set_header X-Forwarded-For $remote_addr;' "${edge}"
grep -Fq 'location ^~ /.well-known/acme-challenge/' "${edge}"
grep -Fq 'ssl_certificate /etc/letsencrypt/live/g7devops.com/fullchain.pem;' "${edge}"
grep -Fq 'fastcgi_pass unix:/run/php/php8.5-fpm-g7devops.sock;' "${bypass}"
if grep -Eq '127\.0\.0\.1:(18080|18081)' "${bypass}"; then
  echo "bypass candidate must not depend on VPSGuard listeners" >&2
  exit 1
fi

grep -Fq 'canonical_host = "www.g7devops.com"' "${config}"
grep -Fq 'trusted_proxy_cidrs = ["127.0.0.1/32", "::1/128"]' "${config}"
grep -Fq 'address = "127.0.0.1:18081"' "${config}"
grep -Fq 'mode = "observe"' "${config}"
grep -Fq 'enabled = false' "${config}"

plan="$(bash scripts/cutover-g7devops.sh --plan --to-edge)"
grep -Fq 'public Nginx TLS -> VPSGuard 127.0.0.1:18080 -> Nginx 127.0.0.1:18081' <<<"${plan}"
grep -Fq 'exact active Nginx/config backup plus deployment snapshot' <<<"${plan}"
grep -Fq "x-vps-guard" scripts/cutover-g7devops-remote.sh
grep -Fq '/usr/local/libexec/vps-guard/deployment-state --snapshot' scripts/cutover-g7devops-remote.sh
grep -Fq 'VPS_GUARD_INGRESS_CONFIRM' scripts/cutover-g7devops-remote.sh

echo "g7devops ingress contract: PASS"
