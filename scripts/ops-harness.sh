#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
mkdir -p target-evidence

cargo run --quiet -p guard-cli -- check-config --config configs/vps-guard.smoke.toml
cargo run --quiet -p guard-cli -- plan --config configs/vps-guard.smoke.toml >target-evidence/ops-plan.json
bash scripts/deploy-g7devops.sh --plan

rg -q '"ssh"' target-evidence/ops-plan.json
rg -q '"certificates"' target-evidence/ops-plan.json
rg -q '"site-data"' target-evidence/ops-plan.json
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify packaging/systemd/*.service
fi

echo "ops harness: PASS"
