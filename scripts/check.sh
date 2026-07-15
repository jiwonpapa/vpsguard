#!/usr/bin/env bash
set -euo pipefail

bash scripts/docs-gate.sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items
cargo test --locked --workspace --all-features
cargo audit --ignore RUSTSEC-2024-0437
cargo deny check

if command -v cargo-machete >/dev/null 2>&1; then
  cargo machete crates
fi

bash scripts/requirements-gate.sh
bash scripts/tests/repository-contracts.sh

(cd web && bun ci && bun run check)
