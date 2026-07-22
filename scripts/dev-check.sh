#!/usr/bin/env bash
set -euo pipefail
exec python3 -m tools.vpsguard_harness dev-check "${1:?usage: scripts/dev-check.sh <python|web|crate>}"
