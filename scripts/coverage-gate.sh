#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mkdir -p target-evidence/coverage

cargo llvm-cov clean --workspace
# 현재 실측 baseline을 하락 불가 ratchet으로 둡니다. process/network adapter는
# integration·fault gate가 담당하고 pure domain은 별도 높은 기준을 적용합니다.
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 43 \
  --lcov --output-path target-evidence/coverage/lcov.info
cargo llvm-cov report --package guard-core --fail-under-lines 80 --summary-only
cargo llvm-cov report --package guard-provider \
  --ignore-filename-regex 'cloudflare\.rs$' \
  --fail-under-lines 90 --summary-only
cargo llvm-cov report --package guard-edge \
  --ignore-filename-regex '/(main|lib|context|proxy|response|runtime|startup)\.rs$' \
  --fail-under-lines 79 --summary-only

echo "coverage gate: PASS"
