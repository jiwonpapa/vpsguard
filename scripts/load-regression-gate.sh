#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
evidence_dir="${repo_root}/target-evidence/load"
mkdir -p "${evidence_dir}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 is required for the load regression gate" >&2
  exit 2
fi

K6_OUT="json=${evidence_dir}/results.json" k6 run "${repo_root}/tests/load/proxy.js"
echo "load regression gate: PASS"
