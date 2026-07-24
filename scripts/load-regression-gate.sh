#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -m tools.vpsguard_harness.load_regression --repo-root "${repo_root}"
