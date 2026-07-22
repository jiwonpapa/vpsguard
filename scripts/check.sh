#!/usr/bin/env bash
set -euo pipefail
trap 'bash scripts/build-storage.sh --auto || true' EXIT
bash scripts/docs-gate.sh
python3 -W error::ResourceWarning -m unittest discover -s tools/tests -p 'test_*.py'
bash scripts/harness-language-gate.sh
bash scripts/build-storage.sh --check-config
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items
cargo test --locked --workspace --all-features
cargo audit --ignore RUSTSEC-2024-0437
cargo deny check
if command -v cargo-machete >/dev/null 2>&1; then cargo machete crates; fi
bash scripts/requirements-gate.sh
bash scripts/tests/repository-contracts.sh

(cd web && bun ci && bun run check)
