#!/usr/bin/env bash
set -euo pipefail
trap 'bash scripts/build-storage.sh --auto || true' EXIT
python3 -m tools.vpsguard_harness dev-check "${1:?usage: scripts/dev-check.sh <python|web|crate>}"
