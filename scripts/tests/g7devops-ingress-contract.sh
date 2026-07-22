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
direct_config="configs/vps-guard.g7devops.direct.toml"
origin_only="configs/nginx/g7devops-origin-only.conf"
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
grep -Fq 'Rust typed exact-file snapshot plus automatic rollback' <<<"${plan}"
grep -Fq 'public_edge_header()' crates/guard-system/src/ingress_state/switch.rs
grep -Fq 'switch_snapshot::create' crates/guard-system/src/ingress_state/switch.rs
grep -Fq 'VPS_GUARD_INGRESS_STAGE' scripts/cutover-g7devops-remote.sh
grep -Fq 'VPS_GUARD_INGRESS_CONFIRM' scripts/cutover-g7devops-remote.sh
grep -Fq '/usr/local/bin/vps-guard ops ingress-switch apply' \
  scripts/cutover-g7devops-remote.sh
if grep -Eq 'trap rollback|deployment-state --snapshot|systemctl (restart|stop|reload)' \
  scripts/cutover-g7devops-remote.sh; then
  echo "cutover remote adapter must not own privileged rollback state" >&2
  exit 1
fi
grep -Fq 'http_bind = "0.0.0.0:80"' "${direct_config}"
grep -Fq 'https_bind = "0.0.0.0:443"' "${direct_config}"
grep -Fq 'cert_file = "tls-cert.pem"' "${direct_config}"
grep -Fq 'key_file = "tls-key.pem"' "${direct_config}"
grep -Fq 'trusted_proxy_cidrs = []' "${direct_config}"
grep -Fq 'listen 127.0.0.1:18081;' "${origin_only}"
grep -Fq 'map $http_x_forwarded_proto $vpsguard_fastcgi_https {' "${origin_only}"
grep -Fq 'fastcgi_param HTTPS $vpsguard_fastcgi_https;' "${origin_only}"
if grep -Eq 'listen .*(:|[[:space:]])(80|443)([[:space:];]|$)' "${origin_only}"; then
  echo "direct origin candidate must not own public 80/443" >&2
  exit 1
fi
grep -Fq 'LoadCredential=tls-key.pem:/etc/letsencrypt/live/g7devops.com/privkey.pem' \
  configs/systemd/g7devops-edge-tls.conf
grep -Fq 'KillSignal=SIGINT' configs/systemd/g7devops-edge-tls.conf
grep -Fq 'ops ingress-state apply-direct --stage' \
  scripts/cutover-g7devops-direct-remote.sh
direct_plan="$(bash scripts/cutover-g7devops-direct.sh --plan)"
grep -Fq 'VPSGuard public 80/443 -> Nginx 127.0.0.1:18081' <<<"${direct_plan}"
grep -Fq 'existing Certbot lineage via systemd credentials' <<<"${direct_plan}"
grep -Fq 'standalone restore: scripts/restore-g7devops-direct.sh' <<<"${direct_plan}"
grep -Fq 'create_direct_candidate_snapshot' \
  crates/guard-system/src/ingress_state/candidate.rs
grep -Fq 'VPS_GUARD_DIRECT_RESTORE_CONFIRM' scripts/restore-g7devops-direct.sh
grep -Fq -- '--retry-connrefused' packaging/certbot/vps-guard-deploy-hook
grep -Fq 'VPS_GUARD_EDGE_HEALTH_HOST=www.g7devops.com' \
  configs/certbot/g7devops-deploy-hook
echo "g7devops ingress contract: PASS"
