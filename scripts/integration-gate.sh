#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${repo_root}/target-evidence/integration"
mkdir -p "${evidence_dir}" /tmp/vps-guard-smoke
find "${evidence_dir}" -maxdepth 1 -type f -delete
rm -f /tmp/vps-guard-smoke/telemetry.sock \
  /tmp/vps-guard-smoke/admin.sock \
  /tmp/vps-guard-smoke/control.sqlite3 \
  /tmp/vps-guard-smoke/control.sqlite3-shm \
  /tmp/vps-guard-smoke/control.sqlite3-wal \
  /tmp/vps-guard-smoke/policy.json \
  /tmp/vps-guard-smoke/tls-cert.pem \
  /tmp/vps-guard-smoke/tls-key.pem \
  /tmp/vps-guard-smoke/login.json \
  "${evidence_dir}/state.json"

origin_pid=""
edge_pid=""
control_pid=""
cleanup() {
  for pid in "${edge_pid}" "${control_pid}" "${origin_pid}"; do
    [[ -z "${pid}" ]] && continue
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  rm -f /tmp/vps-guard-smoke/login.json \
    /tmp/vps-guard-smoke/tls-key.pem \
    /tmp/vps-guard-smoke/tls-cert.pem \
    /tmp/vps-guard-smoke/admin.sock \
    "${evidence_dir}/session.headers" \
    "${evidence_dir}/session.json"
}
trap cleanup EXIT

cd "${repo_root}"
cargo build -p guard-edge -p guard-control -p guard-cli

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=example.test' \
  -addext 'subjectAltName=DNS:example.test,DNS:guard.example.test' \
  -keyout /tmp/vps-guard-smoke/tls-key.pem \
  -out /tmp/vps-guard-smoke/tls-cert.pem >/dev/null 2>&1
chmod 0600 /tmp/vps-guard-smoke/tls-key.pem

python3 tests/fixtures/origin_server.py >"${evidence_dir}/origin.log" 2>&1 &
origin_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:18081/health >"${evidence_dir}/origin-live.json"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.integration.toml" \
VPS_GUARD_STATE="${evidence_dir}/state.json" \
  target/debug/vps-guard-control >"${evidence_dir}/control.log" 2>&1 &
control_pid=$!

curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:17727/health/live >"${evidence_dir}/control-live.txt"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.integration.toml" \
  target/debug/vps-guard-edge >"${evidence_dir}/edge.log" 2>&1 &
edge_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  --dump-header "${evidence_dir}/edge-live.headers" \
  -H 'Host: example.test' http://127.0.0.1:18080/health/live >"${evidence_dir}/edge-live.txt"
grep -Eiq '^x-vpsguard-telemetry-(emitted|dropped|reconnected): [0-9]+' "${evidence_dir}/edge-live.headers"

initial_ready_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: example.test' http://127.0.0.1:18080/health/ready)"
[[ "${initial_ready_status}" == "503" ]]

app_request() {
  local path="$1"
  shift
  curl --silent --show-error --insecure --noproxy '*' \
    --resolve example.test:18443:127.0.0.1 "$@" "https://example.test:18443${path}"
}

admin_request() {
  local path="$1"
  shift
  curl --silent --show-error --insecure --noproxy '*' \
    --resolve guard.example.test:18443:127.0.0.1 "$@" "https://guard.example.test:18443${path}"
}

proxy_body="$(app_request /hello)"
[[ "${proxy_body}" == *'"path": "/hello"'* ]]
[[ "${proxy_body}" == *'"x_forwarded_for": "127.0.0.1"'* ]]
[[ "${proxy_body}" != *'secret='* ]]
ready_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: example.test' http://127.0.0.1:18080/health/ready)"
[[ "${ready_status}" == "200" ]]

invalid_host_status="$(app_request / --output /dev/null --write-out '%{http_code}' -H 'Host: invalid.test')"
[[ "${invalid_host_status}" == "400" ]]

admin_request / >"${evidence_dir}/management-index.html"
grep -Fq '<title>VPSGuard 운영 콘솔</title>' "${evidence_dir}/management-index.html"
management_unknown="$(admin_request /hello)"
[[ "${management_unknown}" == *'<title>VPSGuard 운영 콘솔</title>'* ]]
[[ "${management_unknown}" != *'"path": "/hello"'* ]]
redirect_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --dump-header "${evidence_dir}/management-redirect.headers" \
  -H 'Host: guard.example.test' http://127.0.0.1:18080/)"
[[ "${redirect_status}" == "308" ]]
grep -Eiq '^location: https://guard\.example\.test/' "${evidence_dir}/management-redirect.headers"

# EDGE-008, OPS-001: first-install observe 모드는 설정된 동적 rate limit도 실행하지 않습니다.
for _request in 1 2 3 4; do
  observe_status="$(app_request /hello --output /dev/null --write-out '%{http_code}')"
  [[ "${observe_status}" == "200" ]]
done

login_output="$(target/debug/vps-guard issue-login-code \
  --socket /tmp/vps-guard-smoke/admin.sock --ttl-seconds 300)"
login_code="$(sed -n 's/^VPSGuard 단회 로그인 코드: //p' <<<"${login_output}")"
[[ "${#login_code}" == "64" ]]

# SEC-006: 로그인 code header는 운영 명령을 직접 승인하지 않습니다.
direct_token_status="$(admin_request /api/v1/actions/manual-hold \
  --output /dev/null --write-out '%{http_code}' -X POST \
  -H "X-VPSGuard-Token: ${login_code}" -H 'Idempotency-Key: direct-token-denied')"
[[ "${direct_token_status}" == "401" ]]

umask 077
printf '{"login_code":"%s"}' "${login_code}" >/tmp/vps-guard-smoke/login.json
admin_request /api/v1/session \
  --dump-header "${evidence_dir}/session.headers" \
  --output "${evidence_dir}/session.json" -X POST \
  -H 'Origin: https://guard.example.test' \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/vps-guard-smoke/login.json
reuse_status="$(admin_request /api/v1/session \
  --output /dev/null --write-out '%{http_code}' -X POST \
  -H 'Origin: https://guard.example.test' \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/vps-guard-smoke/login.json)"
[[ "${reuse_status}" == "401" ]]
rm -f /tmp/vps-guard-smoke/login.json
unset login_code login_output

csrf_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["csrf_token"])' "${evidence_dir}/session.json")"
session_cookie="$(sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "${evidence_dir}/session.headers" | tr -d '\r')"
grep -Eiq '^set-cookie: .*; HttpOnly; SameSite=Strict; Secure' "${evidence_dir}/session.headers"

admin_request /api/v1/status -H "Cookie: ${session_cookie}" >"${evidence_dir}/status.json"
admin_request /api/v1/traffic/summary -H "Cookie: ${session_cookie}" >"${evidence_dir}/traffic.json"
admin_request /api/v1/clients -H "Cookie: ${session_cookie}" >"${evidence_dir}/clients.json"
admin_request /api/v1/routes -H "Cookie: ${session_cookie}" >"${evidence_dir}/routes.json"
admin_request /api/v1/incidents -H "Cookie: ${session_cookie}" >"${evidence_dir}/incidents.json"
admin_request /api/v1/traffic/series -H "Cookie: ${session_cookie}" >"${evidence_dir}/series.json"
python3 - "${evidence_dir}/traffic.json" "${evidence_dir}/clients.json" "${evidence_dir}/routes.json" <<'PY'
import json
import sys

traffic = json.load(open(sys.argv[1], encoding="utf-8"))
clients = json.load(open(sys.argv[2], encoding="utf-8"))["items"]
routes = json.load(open(sys.argv[3], encoding="utf-8"))["items"]
assert traffic["requests"] >= 5
assert traffic["response_body_bytes"] > 0
assert traffic["upstream_connections"] >= 1
assert clients and clients[0]["client_ip"] == "127.0.0.1"
assert any(route["response_body_bytes"] > 0 for route in routes)
PY
action_status="$(admin_request /api/v1/actions/manual-hold \
  --output "${evidence_dir}/manual-hold.json" --write-out '%{http_code}' -X POST \
  -H "Cookie: ${session_cookie}" -H "X-CSRF-Token: ${csrf_token}" \
  -H 'Origin: https://guard.example.test' -H 'Idempotency-Key: smoke-hold-1')"
[[ "${action_status}" == "200" ]]
grep -Fq 'MANUAL_HOLD' "${evidence_dir}/manual-hold.json"

admin_request /api/v1/clients -H "Cookie: ${session_cookie}" \
  >"${evidence_dir}/clients-authenticated.json"
python3 - "${evidence_dir}/clients-authenticated.json" <<'PY'
import json
import sys

clients = json.load(open(sys.argv[1], encoding="utf-8"))["items"]
assert clients and clients[0]["client_ip"] == "127.0.0.1"
PY
resume_status="$(admin_request /api/v1/actions/resume-auto \
  --output "${evidence_dir}/resume-auto.json" --write-out '%{http_code}' -X POST \
  -H "Cookie: ${session_cookie}" -H "X-CSRF-Token: ${csrf_token}" \
  -H 'Origin: https://guard.example.test' -H 'Idempotency-Key: smoke-resume-1')"
[[ "${resume_status}" == "200" ]]
grep -Fq 'WATCH' "${evidence_dir}/resume-auto.json"

# SEC-001, SEC-005: session cookie와 CSRF token은 검증 후 artifact에 남기지 않습니다.
rm -f "${evidence_dir}/session.headers" "${evidence_dir}/session.json"

# NFR-003, UI-001: Control 장애는 앱 origin과 ready 상태를 끊지 않습니다.
kill "${control_pid}"
wait "${control_pid}" 2>/dev/null || true
control_pid=""
[[ "$(app_request /hello --output /dev/null --write-out '%{http_code}')" == "200" ]]
[[ "$(admin_request / --output /dev/null --write-out '%{http_code}')" == "502" ]]
[[ "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Host: example.test' http://127.0.0.1:18080/health/ready)" == "200" ]]

echo "integration gate: PASS"
