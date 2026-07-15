#!/usr/bin/env bash
set -euo pipefail

# OPS-010: typed plan 범위, 시간 예산, lock·재개·rollback fault와 빠른
# first-install restore를 한 진입점에서 검증합니다. 실제 VPS 증거는 별도입니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

cd "${repo_root}"
cargo test -q -p guard-system operation

plan="${fixture}/plan.json"
plan_output="$(
  cargo run -q -p guard-cli -- ops plan \
    --operation-id fixture-apply-1 \
    --kind apply \
    --release-id release-0123456789abcdef \
    --source nginx-public \
    --target vps-guard-public \
    --ingress-file /etc/nginx/sites-available/site.conf \
    --certificate /etc/letsencrypt/live/example.com/fullchain.pem \
    --output "${plan}"
)"
grep -Eq '^operation plan saved: .* sha256=[0-9a-f]{64}$' <<<"${plan_output}"
grep -Fq '"public_interruption_ms": 5000' "${plan}"
grep -Fq '"rollback_ms": 10000' "${plan}"
grep -Fq '"operation_ms": 60000' "${plan}"
if grep -Fq '/home/' "${plan}"; then
  echo "operation plan contains a site tree" >&2
  exit 1
fi

if cargo run -q -p guard-cli -- ops plan \
  --operation-id fixture-unsafe-1 \
  --kind apply \
  --release-id release-0123456789abcdef \
  --source nginx-public \
  --target vps-guard-public \
  --ingress-file /home/example/public_html \
  --certificate /etc/letsencrypt/live/example.com/fullchain.pem \
  >/dev/null 2>&1; then
  echo "site tree was accepted as an ingress snapshot" >&2
  exit 1
fi

SECONDS=0
bash scripts/tests/deployment-restore-harness.sh >/dev/null
if (( SECONDS > 30 )); then
  echo "first-install restore fixture exceeded 30 seconds: ${SECONDS}s" >&2
  exit 1
fi
if rg -n 'tree_hash|find .*public_html|sha256sum .*public_html' scripts/deployment-state.sh; then
  echo "deployment restore still scans the site tree" >&2
  exit 1
fi

echo "operation harness: PASS (restore_fixture_seconds=${SECONDS})"
