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
  /tmp/vps-guard-smoke/protocol-body.bin \
  /tmp/vps-guard-smoke/protocol-only-telemetry.sock \
  /tmp/vps-guard-smoke/security-telemetry.sock \
  "${evidence_dir}/state.json"

origin_pid=""
edge_pid=""
protocol_edge_pid=""
security_edge_pid=""
control_pid=""
stop_process() {
  local pid="$1"
  [[ -z "${pid}" ]] && return
  kill "${pid}" 2>/dev/null || true
  for _attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" 2>/dev/null || true
      return
    fi
    sleep 0.05
  done
  kill -KILL "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}
cleanup() {
  for pid in "${security_edge_pid}" "${protocol_edge_pid}" "${edge_pid}" "${control_pid}" "${origin_pid}"; do
    stop_process "${pid}"
  done
  rm -f /tmp/vps-guard-smoke/login.json \
    /tmp/vps-guard-smoke/tls-key.pem \
    /tmp/vps-guard-smoke/tls-cert.pem \
    /tmp/vps-guard-smoke/protocol-body.bin \
    /tmp/vps-guard-smoke/protocol-only-telemetry.sock \
    /tmp/vps-guard-smoke/security-telemetry.sock \
    /tmp/vps-guard-smoke/admin.sock \
    "${evidence_dir}/session.headers" \
    "${evidence_dir}/session.json"
  bash "${repo_root}/scripts/build-storage.sh" --auto || true
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

VPS_GUARD_TEST_ORIGIN_PORT=28081 \
  python3 tests/fixtures/origin_server.py >"${evidence_dir}/origin.log" 2>&1 &
origin_pid=$!
curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:28081/health >"${evidence_dir}/origin-live.json"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.integration.toml" \
VPS_GUARD_STATE="${evidence_dir}/state.json" \
RUST_LOG=guard_control=debug,vps_guard_control=debug \
  target/debug/vps-guard-control >"${evidence_dir}/control.log" 2>&1 &
control_pid=$!

curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  --dump-header "${evidence_dir}/control-live.headers" \
  http://127.0.0.1:27727/health/live >"${evidence_dir}/control-live.txt"
grep -Eiq '^x-request-id: guard-[0-9a-f]{32}-[0-9a-f]{16}' "${evidence_dir}/control-live.headers"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.integration.toml" \
RUST_LOG=guard_edge=debug,vps_guard_edge=debug,pingora=warn \
  target/debug/vps-guard-edge >"${evidence_dir}/edge.log" 2>&1 &
edge_pid=$!
curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  --dump-header "${evidence_dir}/edge-live.headers" \
  -H 'Host: example.test' http://127.0.0.1:28080/health/live >"${evidence_dir}/edge-live.txt"
grep -Eiq '^x-vpsguard-telemetry-(emitted|dropped|reconnected): [0-9]+' "${evidence_dir}/edge-live.headers"

initial_ready_status="$(curl --disable --silent --output /dev/null --write-out '%{http_code}' -H 'Host: example.test' http://127.0.0.1:28080/health/ready)"
[[ "${initial_ready_status}" == "503" ]]

app_request() {
  local path="$1"
  shift
  curl --disable --silent --show-error --insecure --noproxy '*' \
    --resolve example.test:28443:127.0.0.1 "$@" "https://example.test:28443${path}"
}

protocol_request() {
  local path="$1"
  shift
  curl --disable --silent --show-error --noproxy '*' \
    -H 'Host: example.test' "$@" "http://127.0.0.1:28082${path}"
}

protocol_tls_request() {
  local path="$1"
  shift
  curl --disable --silent --show-error --insecure --http1.1 --noproxy '*' \
    --resolve example.test:28444:127.0.0.1 "$@" "https://example.test:28444${path}"
}

security_request() {
  local path="$1"
  shift
  curl --disable --silent --show-error --noproxy '*' \
    -H 'Host: example.test' "$@" "http://127.0.0.1:28083${path}"
}

admin_request() {
  local path="$1"
  shift
  curl --disable --silent --show-error --insecure --noproxy '*' \
    --resolve guard.example.test:28443:127.0.0.1 "$@" "https://guard.example.test:28443${path}"
}

app_request /hello \
  --dump-header "${evidence_dir}/proxy-request.headers" \
  --output "${evidence_dir}/proxy-request.json"
proxy_body="$(<"${evidence_dir}/proxy-request.json")"
[[ "${proxy_body}" == *'"path": "/hello"'* ]]
[[ "${proxy_body}" == *'"x_forwarded_for": "127.0.0.1"'* ]]
[[ "${proxy_body}" != *'secret='* ]]
proxy_request_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["x_request_id"])' <<<"${proxy_body}")"
response_request_id="$(sed -n 's/^x-request-id:[[:space:]]*//Ip' "${evidence_dir}/proxy-request.headers" | tr -d '\r' | head -1)"
[[ "${proxy_request_id}" =~ ^guard-[0-9a-f]{32}-[0-9a-f]{16}$ ]]
[[ "${response_request_id}" == "${proxy_request_id}" ]]
spoofed_request_id="$(app_request /hello -H 'X-Request-ID: client-controlled' | python3 -c 'import json,sys; print(json.load(sys.stdin)["x_request_id"])')"
[[ "${spoofed_request_id}" != 'client-controlled' ]]
app_request /security-headers \
  --dump-header "${evidence_dir}/app-security.headers" \
  --output /dev/null
grep -Eiq '^x-content-type-options: nosniff' "${evidence_dir}/app-security.headers"
grep -Eiq '^referrer-policy: strict-origin-when-cross-origin' "${evidence_dir}/app-security.headers"
grep -Eiq '^content-security-policy-report-only: .*script-src .self.' "${evidence_dir}/app-security.headers"
grep -Eiq '^strict-transport-security: max-age=86400' "${evidence_dir}/app-security.headers"
if grep -Eiq '^(server|x-powered-by|x-aspnet-version):' "${evidence_dir}/app-security.headers"; then
  echo "origin version header leaked through edge" >&2
  exit 1
fi
ready_status="$(curl --disable --silent --output /dev/null --write-out '%{http_code}' -H 'Host: example.test' http://127.0.0.1:28080/health/ready)"
[[ "${ready_status}" == "200" ]]

# EDGE-013: protocol_only는 G7 app profile과 동적 판정을 건너뛰지만
# HTTP parsing, Host, forwarded header, body 상한과 telemetry 경계는 유지합니다.
VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.protocol-only.integration.toml" \
  target/debug/vps-guard-edge >"${evidence_dir}/protocol-only-edge.log" 2>&1 &
protocol_edge_pid=$!
curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  -H 'Host: example.test' http://127.0.0.1:28082/health/live \
  >"${evidence_dir}/protocol-only-live.txt"
# health listener가 먼저 준비될 수 있으므로 TLS listener도 별도로 대기합니다.
protocol_tls_request /health/live \
  --retry 40 --retry-connrefused --retry-delay 0 \
  --output "${evidence_dir}/protocol-only-tls-live.txt"
protocol_request /api/auth/login \
  --dump-header "${evidence_dir}/protocol-only-http-redirect.headers" \
  --output /dev/null
grep -Eq '^HTTP/[0-9.]+ 308' "${evidence_dir}/protocol-only-http-redirect.headers"
grep -Eiq '^location: https://example\.test/api/auth/login' "${evidence_dir}/protocol-only-http-redirect.headers"
for _request in 1 2 3 4; do
  [[ "$(protocol_tls_request /api/auth/login --output /dev/null --write-out '%{http_code}')" == "200" ]]
done
[[ "$(protocol_tls_request /protocol-only-tls --output /dev/null --write-out '%{http_code}')" == "200" ]]
protocol_tls_request /protocol-only-tls \
  --dump-header "${evidence_dir}/protocol-only-security.headers" \
  --output /dev/null
grep -Eiq '^x-content-type-options: nosniff' "${evidence_dir}/protocol-only-security.headers"
grep -Eiq '^strict-transport-security: max-age=86400' "${evidence_dir}/protocol-only-security.headers"
if grep -Eiq '^content-security-policy(-report-only)?:' "${evidence_dir}/protocol-only-security.headers"; then
  echo "protocol_only unexpectedly applied app CSP" >&2
  exit 1
fi
for unsafe_method in CONNECT TRACE TRACK; do
  [[ "$(protocol_tls_request / --request "${unsafe_method}" --output /dev/null --write-out '%{http_code}')" == "405" ]]
done
protocol_spoof="$(protocol_tls_request /protocol-only -H 'X-Forwarded-For: 203.0.113.7')"
[[ "${protocol_spoof}" == *'"x_forwarded_for": "127.0.0.1"'* ]]
[[ "${protocol_spoof}" != *'203.0.113.7'* ]]
[[ "$(protocol_tls_request / --output /dev/null --write-out '%{http_code}' -H 'Host: invalid.test')" == "400" ]]
python3 -c 'from pathlib import Path; Path("/tmp/vps-guard-smoke/protocol-body.bin").write_bytes(b"x" * 2048)'
[[ "$(protocol_tls_request /upload --output /dev/null --write-out '%{http_code}' -X POST --data-binary @/tmp/vps-guard-smoke/protocol-body.bin)" == "200" ]]
[[ "$(protocol_tls_request /regular --output /dev/null --write-out '%{http_code}' -X POST --data-binary @/tmp/vps-guard-smoke/protocol-body.bin)" == "413" ]]
python3 - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 28082), timeout=2) as connection:
    connection.sendall(b"SSH-2.0-not-http\r\n")
    connection.settimeout(1)
    try:
        response = connection.recv(4096)
    except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
        response = b""
assert b'"path"' not in response
PY
printf '%s\n' \
  'profiled_http=pass' \
  'protocol_only_http=pass' \
  'protocol_only_tls=pass' \
  'host_forwarded_body_invariants=pass' \
  'owned_port_non_http_rejected=pass' \
  >"${evidence_dir}/inspection-modes.txt"
stop_process "${protocol_edge_pid}"
protocol_edge_pid=""

# SEC-010: G7 인증 경로는 search·일반 경로와 분리된 bounded client 한도를 사용합니다.
VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.security.integration.toml" \
  target/debug/vps-guard-edge >"${evidence_dir}/security-edge.log" 2>&1 &
security_edge_pid=$!
curl --disable --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  -H 'Host: example.test' http://127.0.0.1:28083/health/live \
  >"${evidence_dir}/security-live.txt"
for _request in 1 2; do
  [[ "$(security_request /api/auth/login --request POST --data 'credential=redacted' --output /dev/null --write-out '%{http_code}')" == "200" ]]
done
[[ "$(security_request /api/auth/login --request POST --data 'credential=redacted' \
  --dump-header "${evidence_dir}/auth-throttle.headers" \
  --output /dev/null --write-out '%{http_code}')" == "429" ]]
grep -Eiq '^retry-after: 60' "${evidence_dir}/auth-throttle.headers"
[[ "$(security_request /api/search --output /dev/null --write-out '%{http_code}')" == "200" ]]
[[ "$(security_request /hello --output /dev/null --write-out '%{http_code}')" == "200" ]]
printf '%s\n' \
  'dangerous_methods_rejected=pass' \
  'baseline_headers=pass' \
  'gnuboard7_csp_report_only=pass' \
  'protocol_only_app_csp_skipped=pass' \
  'gnuboard7_auth_limit_isolated=pass' \
  >"${evidence_dir}/app-security.txt"
stop_process "${security_edge_pid}"
security_edge_pid=""

# EDGE-011, SEC-011: query·authorization·body secret은 구조화 log나 evidence에 남기지 않습니다.
app_request '/hello?token=VPSGUARD_INTEGRATION_QUERY_SECRET' \
  --header 'Authorization: Bearer VPSGUARD_INTEGRATION_HEADER_SECRET' \
  --output /dev/null
app_request /hello --request POST \
  --data 'password=VPSGUARD_INTEGRATION_BODY_SECRET' \
  --output /dev/null
if grep -R -F -e 'VPSGUARD_INTEGRATION_QUERY_SECRET' \
  -e 'VPSGUARD_INTEGRATION_HEADER_SECRET' \
  -e 'VPSGUARD_INTEGRATION_BODY_SECRET' "${evidence_dir}"; then
  echo "request secret leaked into integration evidence" >&2
  exit 1
fi

# OBS-012, OBS-013: request ID와 operational JSON 공통 field를 같은 증거에서 확인합니다.
grep -Fq '"log_schema_version":1' "${evidence_dir}/edge.log"
grep -Fq '"component":"guard-edge"' "${evidence_dir}/edge.log"
grep -Fq "\"request_id\":\"${proxy_request_id}\"" "${evidence_dir}/edge.log"
grep -Fq '"log_schema_version":1' "${evidence_dir}/control.log"
grep -Fq '"component":"guard-control"' "${evidence_dir}/control.log"

invalid_host_status="$(app_request / --output /dev/null --write-out '%{http_code}' -H 'Host: invalid.test')"
[[ "${invalid_host_status}" == "400" ]]

admin_request / >"${evidence_dir}/management-index.html"
grep -Fq '<title>VPSGuard 운영 콘솔</title>' "${evidence_dir}/management-index.html"
management_unknown="$(admin_request /hello)"
[[ "${management_unknown}" == *'<title>VPSGuard 운영 콘솔</title>'* ]]
[[ "${management_unknown}" != *'"path": "/hello"'* ]]
redirect_status="$(curl --disable --silent --output /dev/null --write-out '%{http_code}' \
  --dump-header "${evidence_dir}/management-redirect.headers" \
  -H 'Host: guard.example.test' http://127.0.0.1:28080/)"
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
[[ "$(curl --disable --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Host: example.test' http://127.0.0.1:28080/health/ready)" == "200" ]]

echo "integration gate: PASS"
