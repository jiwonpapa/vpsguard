#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${repo_root}/target-evidence/load"
mkdir -p "${evidence_dir}"

origin_pid=""
edge_pid=""
cleanup() {
  [[ -z "${edge_pid}" ]] || kill "${edge_pid}" 2>/dev/null || true
  [[ -z "${origin_pid}" ]] || kill "${origin_pid}" 2>/dev/null || true
}
trap cleanup EXIT

cd "${repo_root}"
cargo build --locked -p guard-edge
python3 tests/fixtures/origin_server.py >"${evidence_dir}/origin.log" 2>&1 &
origin_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  http://127.0.0.1:18081/health >"${evidence_dir}/origin-live.json"
VPS_GUARD_CONFIG="${repo_root}/configs/vps-guard.example.toml" \
  target/debug/vps-guard-edge >"${evidence_dir}/edge.log" 2>&1 &
edge_pid=$!
curl --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
  -H 'Host: example.com' http://127.0.0.1:18080/health/live >"${evidence_dir}/edge-live.txt"

export TARGET_URL="http://127.0.0.1:18080/hello"
export TARGET_HOST="example.com"
export VUS="${VUS:-10}"
export DURATION="${DURATION:-10s}"
if command -v k6 >/dev/null 2>&1; then
  k6 run --summary-export "${evidence_dir}/summary.json" "${repo_root}/tests/load/proxy.js"
elif command -v docker >/dev/null 2>&1; then
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "${repo_root}:/work" \
    -e TARGET_URL -e TARGET_HOST -e VUS -e DURATION \
    grafana/k6:0.55.2 run --summary-export /work/target-evidence/load/summary.json \
    /work/tests/load/proxy.js
else
  echo "k6 or docker is required for the load regression gate" >&2
  exit 2
fi
echo "load regression gate: PASS"
