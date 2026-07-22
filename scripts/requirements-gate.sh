#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
case "${1:---development}" in
  --development) exec python3 -m tools.vpsguard_harness requirements ;;
  --release) exec python3 -m tools.vpsguard_harness requirements --release ;;
  *) echo "usage: $0 [--development|--release]" >&2; exit 2 ;;
esac
