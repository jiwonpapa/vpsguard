#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${repo_root}/target-evidence/integration"
mkdir -p "${evidence_dir}" /tmp/vps-guard-smoke
rm -f /tmp/vps-guard-smoke/telemetry.sock \
  /tmp/vps-guard-smoke/control.sqlite3 \
  /tmp/vps-guard-smoke/control.sqlite3-shm \
  /tmp/vps-guard-smoke/control.sqlite3-wal \
  /tmp/vps-guard-smoke/policy.json \
  "${evidence_dir}/state.json"

origin_pid=""
edge_pid=""
control_pid=""
cleanup() {
  [[ -z "${edge_pid}" ]] || kill "${edge_pid}" 2>/dev/null || true
  [[ -z "${control_pid}" ]] || kill "${control_pid}" 2>/dev/null || true
  [[ -z "${origin_pid}" ]] || kill "${origin_pid}" 2>/dev/null || true
}
trap cleanup EXIT

cd "${repo_root}"
cargo build -p guard-edge -p guard-control

python3 tests/fixtures/origin_server.py >"${evidence_dir}/origin.log" 2>&1 &
origin_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:18081/health >"${evidence_dir}/origin-live.json"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.smoke.toml" \
VPS_GUARD_STATE="${evidence_dir}/state.json" \
VPS_GUARD_ACTION_TOKEN="smoke-token" \
  target/debug/vps-guard-control >"${evidence_dir}/control.log" 2>&1 &
control_pid=$!

curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:17727/health/live >"${evidence_dir}/control-live.txt"

VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.smoke.toml" \
  target/debug/vps-guard-edge >"${evidence_dir}/edge.log" 2>&1 &
edge_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  -H 'Host: example.test' http://127.0.0.1:18080/health/live >"${evidence_dir}/edge-live.txt"

proxy_body="$(curl --silent --show-error -H 'Host: example.test' http://127.0.0.1:18080/hello)"
[[ "${proxy_body}" == *'"path": "/hello"'* ]]
[[ "${proxy_body}" == *'"x_forwarded_for": "127.0.0.1"'* ]]
[[ "${proxy_body}" != *'secret='* ]]

invalid_host_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: invalid.test' http://127.0.0.1:18080/)"
[[ "${invalid_host_status}" == "400" ]]

curl --silent --output /dev/null -H 'Host: example.test' http://127.0.0.1:18080/hello
rate_limited_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Host: example.test' http://127.0.0.1:18080/hello)"
[[ "${rate_limited_status}" == "429" ]]

curl --silent --show-error http://127.0.0.1:17727/api/v1/status >"${evidence_dir}/status.json"
curl --silent --show-error http://127.0.0.1:17727/api/v1/traffic/summary >"${evidence_dir}/traffic.json"
curl --silent --show-error http://127.0.0.1:17727/api/v1/clients >"${evidence_dir}/clients.json"
curl --silent --show-error http://127.0.0.1:17727/api/v1/routes >"${evidence_dir}/routes.json"
curl --silent --show-error http://127.0.0.1:17727/api/v1/incidents >"${evidence_dir}/incidents.json"
curl --silent --show-error http://127.0.0.1:17727/api/v1/traffic/series >"${evidence_dir}/series.json"
python3 - "${evidence_dir}/traffic.json" "${evidence_dir}/clients.json" "${evidence_dir}/routes.json" <<'PY'
import json
import sys

traffic = json.load(open(sys.argv[1], encoding="utf-8"))
clients = json.load(open(sys.argv[2], encoding="utf-8"))["items"]
routes = json.load(open(sys.argv[3], encoding="utf-8"))["items"]
assert traffic["requests"] >= 5
assert traffic["response_body_bytes"] > 0
assert traffic["upstream_connections"] >= 1
assert clients and clients[0]["client_ip"].endswith("/24")
assert any(route["response_body_bytes"] > 0 for route in routes)
PY
action_status="$(curl --silent --output "${evidence_dir}/manual-hold.json" --write-out '%{http_code}' \
  -X POST -H 'X-VPSGuard-Token: smoke-token' -H 'Idempotency-Key: smoke-hold-1' \
  http://127.0.0.1:17727/api/v1/actions/manual-hold)"
[[ "${action_status}" == "200" ]]
grep -Fq 'MANUAL_HOLD' "${evidence_dir}/manual-hold.json"

curl --silent --show-error --dump-header "${evidence_dir}/session.headers" \
  --output "${evidence_dir}/session.json" -X POST \
  -H 'X-VPSGuard-Token: smoke-token' http://127.0.0.1:17727/api/v1/session
csrf_token="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["csrf_token"])' "${evidence_dir}/session.json")"
session_cookie="$(sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "${evidence_dir}/session.headers" | tr -d '\r')"
curl --silent --show-error -H "Cookie: ${session_cookie}" \
  http://127.0.0.1:17727/api/v1/clients >"${evidence_dir}/clients-authenticated.json"
python3 - "${evidence_dir}/clients-authenticated.json" <<'PY'
import json
import sys

clients = json.load(open(sys.argv[1], encoding="utf-8"))["items"]
assert clients and clients[0]["client_ip"] == "127.0.0.1"
PY
resume_status="$(curl --silent --output "${evidence_dir}/resume-auto.json" --write-out '%{http_code}' \
  -X POST -H "Cookie: ${session_cookie}" -H "X-CSRF-Token: ${csrf_token}" \
  -H 'Idempotency-Key: smoke-resume-1' \
  http://127.0.0.1:17727/api/v1/actions/resume-auto)"
[[ "${resume_status}" == "200" ]]
grep -Fq 'WATCH' "${evidence_dir}/resume-auto.json"

# SEC-001, SEC-005: session cookie와 CSRF token은 검증 후 artifact에 남기지 않습니다.
rm -f "${evidence_dir}/session.headers" "${evidence_dir}/session.json"

echo "integration gate: PASS"
