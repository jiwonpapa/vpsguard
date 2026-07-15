#!/usr/bin/env bash
set -euo pipefail

# EDGE-001, EDGE-002, TLS-005, OPS-003: VPSGuard가 public 80/443을 직접 소유하고
# Nginx는 loopback HTTP/PHP-FPM origin으로만 남기는 g7devops 전환 트랜잭션입니다.
stage="${1:-}"
active_nginx="/etc/nginx/sites-available/g7.conf"
active_config="/etc/vps-guard/config.toml"
dropin_dir="/etc/systemd/system/vps-guard-edge.service.d"
dropin="${dropin_dir}/30-g7devops-tls.conf"
bypass="/etc/vps-guard/nginx/public-bypass.conf"
default_deny="/etc/nginx/sites-enabled/g7-default-deny.conf"
generic_certbot_hook="/usr/local/libexec/vps-guard/certbot-deploy-hook"
site_certbot_hook="/etc/letsencrypt/renewal-hooks/deploy/vps-guard"
headers=""
default_deny_was_enabled=false
default_deny_target=""
generic_hook_existed=false
site_hook_existed=false
current_direct=false

[[ "${EUID}" -eq 0 ]] || { echo "root is required" >&2; exit 2; }
[[ "${stage}" =~ ^/tmp/vpsguard-direct\.[A-Za-z0-9]+$ ]] || {
  echo "invalid staging path" >&2
  exit 2
}
[[ "${VPS_GUARD_DIRECT_CONFIRM:-}" == "g7devops:direct-tls" ]] || {
  echo "VPS_GUARD_DIRECT_CONFIRM=g7devops:direct-tls is required" >&2
  exit 2
}

for file in \
  direct.toml \
  origin-only.conf \
  edge-tls.conf \
  certbot-deploy-hook \
  g7-certbot-deploy-hook; do
  [[ -f "${stage}/${file}" && ! -L "${stage}/${file}" ]] || {
    echo "missing staged file: ${file}" >&2
    exit 2
  }
done

systemctl is-active --quiet nginx.service
systemctl is-active --quiet php8.5-fpm.service
systemctl is-active --quiet vps-guard-control.service
[[ -f "${bypass}" && ! -L "${bypass}" ]]
/usr/local/bin/vps-guard check-config --config "${stage}/direct.toml" >/dev/null

test_config="$(mktemp /etc/nginx/vpsguard-direct.XXXXXX.conf)"
cleanup_test_config() { rm -f "${test_config}"; }
trap cleanup_test_config EXIT
awk -v candidate="${stage}/origin-only.conf" '
  $1 == "include" && $2 == "/etc/nginx/sites-enabled/*;" {
    print "\tinclude " candidate ";"
    replaced = 1
    next
  }
  { print }
  END { exit replaced ? 0 : 1 }
' /etc/nginx/nginx.conf >"${test_config}"
nginx -t -p /etc/nginx/ -c "${test_config}" >/dev/null
cleanup_test_config
trap - EXIT

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/var/lib/vps-guard/backups/direct-${timestamp}"
install -d -m 0750 "${backup}"
install -m 0644 "${active_nginx}" "${backup}/g7.conf"
install -m 0640 "${active_config}" "${backup}/config.toml"
if [[ -f "${dropin}" ]]; then
  install -m 0644 "${dropin}" "${backup}/edge-tls.conf"
  touch "${backup}/dropin-existed"
fi
if [[ -L "${default_deny}" ]]; then
  default_deny_was_enabled=true
  default_deny_target="$(readlink "${default_deny}")"
fi
if [[ -f "${generic_certbot_hook}" ]]; then
  generic_hook_existed=true
  install -m 0755 "${generic_certbot_hook}" "${backup}/certbot-deploy-hook"
fi
if [[ -f "${site_certbot_hook}" ]]; then
  site_hook_existed=true
  install -m 0755 "${site_certbot_hook}" "${backup}/g7-certbot-deploy-hook"
fi
certificate_fingerprint="$(openssl x509 \
  -in /etc/letsencrypt/live/g7devops.com/fullchain.pem \
  -noout -fingerprint -sha256)"
if ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):443.*vps-guard-edge'; then
  current_direct=true
fi

stop_edge_now() {
  systemctl stop --no-block vps-guard-edge.service || true
  sleep 0.2
  systemctl kill --kill-whom=main --signal=SIGKILL vps-guard-edge.service || true
  for _ in {1..40}; do
    state="$(systemctl show vps-guard-edge.service -p ActiveState --value)"
    [[ "${state}" == "inactive" || "${state}" == "failed" ]] && return 0
    sleep 0.1
  done
  return 1
}

rollback() {
  rc=$?
  [[ ${rc} -eq 0 ]] && return
  trap - EXIT
  [[ -z "${headers}" ]] || rm -f "${headers}"
  echo "direct TLS cutover failed; restoring prior topology" >&2
  stop_edge_now || true
  install -m 0640 -o root -g vps-guard "${backup}/config.toml" "${active_config}"
  if [[ -f "${backup}/dropin-existed" ]]; then
    install -d -m 0755 "${dropin_dir}"
    install -m 0644 -o root -g root "${backup}/edge-tls.conf" "${dropin}"
  else
    rm -f "${dropin}"
  fi
  install -m 0644 -o root -g root "${backup}/g7.conf" "${active_nginx}"
  if [[ "${default_deny_was_enabled}" == true ]]; then
    ln -sfn "${default_deny_target}" "${default_deny}"
  fi
  if [[ "${generic_hook_existed}" == true ]]; then
    install -d -m 0755 "$(dirname "${generic_certbot_hook}")"
    install -m 0755 -o root -g root \
      "${backup}/certbot-deploy-hook" "${generic_certbot_hook}"
  else
    rm -f "${generic_certbot_hook}"
  fi
  if [[ "${site_hook_existed}" == true ]]; then
    install -d -m 0755 "$(dirname "${site_certbot_hook}")"
    install -m 0755 -o root -g root \
      "${backup}/g7-certbot-deploy-hook" "${site_certbot_hook}"
  else
    rm -f "${site_certbot_hook}"
  fi
  systemctl daemon-reload
  nginx -t || true
  systemctl restart nginx.service || true
  systemctl start vps-guard-edge.service || true
  echo "rollback backup=${backup}" >&2
  exit "${rc}"
}
trap rollback EXIT

# Nginx TLS topology에서 처음 들어올 때만 bypass를 먼저 열어 edge 정지 중에도
# 사이트를 보존합니다. 이미 direct TLS이면 빠른 edge 재시작 경로를 사용합니다.
if [[ "${current_direct}" == false ]]; then
  install -m 0644 -o root -g root "${bypass}" "${active_nginx}"
  nginx -t >/dev/null
  systemctl reload nginx.service
  curl --fail --silent --show-error https://www.g7devops.com/ >/dev/null
fi
stop_edge_now

install -m 0640 -o root -g vps-guard "${stage}/direct.toml" "${active_config}"
install -d -m 0755 "${dropin_dir}"
install -m 0644 -o root -g root "${stage}/edge-tls.conf" "${dropin}"
install -m 0644 -o root -g root "${stage}/origin-only.conf" "${active_nginx}"
if [[ "${default_deny_was_enabled}" == true ]]; then
  rm -f "${default_deny}"
fi
systemctl daemon-reload
/usr/local/bin/vps-guard check-config --config "${active_config}" >/dev/null
nginx -t >/dev/null

# 80/443 port owner를 Nginx에서 VPSGuard로 넘기는 유일한 짧은 전환 구간입니다.
systemctl stop nginx.service
systemctl start nginx.service
systemctl start vps-guard-edge.service

for _ in {1..80}; do
  if curl --fail --silent --show-error \
    -H 'Host: www.g7devops.com' http://127.0.0.1/health/live >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl --fail --silent --show-error \
  -H 'Host: www.g7devops.com' http://127.0.0.1/health/live >/dev/null

headers="$(mktemp)"
curl --fail --silent --show-error --resolve www.g7devops.com:443:127.0.0.1 \
  --dump-header "${headers}" --output /dev/null https://www.g7devops.com/
grep -Eiq '^x-vps-guard:[[:space:]]*guard-edge' "${headers}"
rm -f "${headers}"
headers=""

served_fingerprint="$(openssl s_client -connect 127.0.0.1:443 \
  -servername www.g7devops.com </dev/null 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256)"
[[ "${served_fingerprint}" == "${certificate_fingerprint}" ]]
ss -H -ltnp | grep -Eq '127\.0\.0\.1:18081.*nginx'
ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):443.*vps-guard-edge'
ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):80.*vps-guard-edge'
systemctl is-active --quiet nginx.service
systemctl is-active --quiet vps-guard-edge.service
curl --fail --silent --show-error https://www.g7devops.com/login >/dev/null

install -d -m 0755 \
  "$(dirname "${generic_certbot_hook}")" \
  "$(dirname "${site_certbot_hook}")"
install -m 0755 -o root -g root \
  "${stage}/certbot-deploy-hook" "${generic_certbot_hook}"
install -m 0755 -o root -g root \
  "${stage}/g7-certbot-deploy-hook" "${site_certbot_hook}"

trap - EXIT
echo "g7devops direct TLS cutover: PASS"
echo "topology=VPSGuard:80/443->Nginx:127.0.0.1:18081->PHP-FPM"
echo "backup=${backup}"
