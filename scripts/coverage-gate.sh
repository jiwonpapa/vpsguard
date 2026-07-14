#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mkdir -p target-evidence/coverage

cargo llvm-cov clean --workspace
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 80 \
  --lcov --output-path target-evidence/coverage/lcov.info
cargo llvm-cov --locked --package guard-core --lib --fail-under-lines 90 --summary-only
cargo llvm-cov --locked --package guard-provider --lib --fail-under-lines 90 --summary-only
cargo llvm-cov --locked --package guard-edge --lib --fail-under-lines 85 --summary-only

echo "coverage gate: PASS"
