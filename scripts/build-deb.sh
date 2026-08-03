#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle="${1:?usage: scripts/build-deb.sh RELEASE_BUNDLE [OUTPUT]}"
output="${2:-}"
cd "${repo_root}"
expected_commit="$(git rev-parse --verify HEAD)"
if [[ -n "${output}" ]]; then
  python3 -m tools.vpsguard_harness.debian_package \
    "${bundle}" --output "${output}" --expected-commit "${expected_commit}"
else
  python3 -m tools.vpsguard_harness.debian_package \
    "${bundle}" --expected-commit "${expected_commit}"
fi
