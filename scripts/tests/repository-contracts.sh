#!/usr/bin/env bash
set -euo pipefail

# OPS-007, NFR-005: 저장소 게이트는 CI 기본 이미지에서 재현되고 미수집 증거를
# 릴리스 완료로 오인하지 않아야 합니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

bash scripts/requirements-gate.sh

release_output="$(mktemp)"
trap 'rm -f "${release_output}"' EXIT
if bash scripts/requirements-gate.sh --release >"${release_output}" 2>&1; then
  echo "release requirement gate unexpectedly passed without VPS evidence" >&2
  exit 1
fi
grep -Fq "release gate blocked" "${release_output}"

if grep -En '\brg([[:space:]]|$)' scripts/*.sh packaging/certbot/*; then
  echo "runtime harness must not depend on ripgrep being preinstalled" >&2
  exit 1
fi

grep -Fq 'pre-MVP' README.md
grep -Fq 'pre-MVP' specs/product/11-mvp-implementation-status.md
grep -Fq 'CODE_ONLY' specs/product/verification-status.tsv

if grep -Fq 'vpsguard-0.1.0' .github/workflows/release.yml; then
  echo "release workflow must derive the workspace version" >&2
  exit 1
fi
grep -Fq 'SHA256SUMS' scripts/deploy-g7devops.sh
grep -Fq 'VPS_GUARD_EDGE_HEALTH_URL' scripts/update-release.sh
grep -Fq 'VPS_GUARD_BYPASS_VERIFIED' scripts/uninstall.sh

echo "repository contract tests: PASS"
