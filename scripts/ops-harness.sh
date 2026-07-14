#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
mkdir -p target-evidence

cargo run --quiet -p guard-cli -- check-config --config configs/vps-guard.smoke.toml
cargo run --quiet -p guard-cli -- plan --config configs/vps-guard.smoke.toml >target-evidence/ops-plan.json
bash scripts/deploy-g7devops.sh --plan
bash scripts/ingress-transaction.sh --to-edge --plan >target-evidence/ingress-edge-plan.txt
bash scripts/ingress-transaction.sh --to-nginx --plan >target-evidence/ingress-bypass-plan.txt
bash scripts/update-release.sh --plan >target-evidence/update-plan.txt
bash scripts/uninstall.sh --plan >target-evidence/uninstall-plan.txt

grep -Fq '"ssh"' target-evidence/ops-plan.json
grep -Fq '"certificates"' target-evidence/ops-plan.json
grep -Fq '"site-data"' target-evidence/ops-plan.json
grep -Fq 'preserve: SSH, certificates, site data' target-evidence/ingress-edge-plan.txt
grep -Fq '/etc/letsencrypt' target-evidence/update-plan.txt
grep -Fq 'remove owned path: /usr/local/bin/vps-guard' target-evidence/uninstall-plan.txt
grep -Fq 'remove owned nft table: inet vps_guard' target-evidence/uninstall-plan.txt
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify packaging/systemd/*.service
fi

echo "ops harness: PASS"
