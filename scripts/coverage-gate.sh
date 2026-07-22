#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
trap 'bash scripts/build-storage.sh --auto || true' EXIT

mkdir -p target-evidence/coverage

cargo llvm-cov clean --workspace
# NFR-011: 전체 테스트를 한 번만 실행하고 versioned LCOV baseline에서
# workspace와 named production adapter를 함께 검증합니다.
cargo llvm-cov --locked --workspace --all-features --lcov \
  --output-path target-evidence/coverage/lcov.info
python3 -m tools.vpsguard_harness coverage

echo "coverage gate: PASS"
