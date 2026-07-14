#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
cargo test --workspace --all-features
cargo audit
cargo deny check

(cd web && bun install --frozen-lockfile && bun run build && bun test)
