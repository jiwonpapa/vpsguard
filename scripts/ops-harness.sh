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
  systemd_log="$(mktemp)"
  filtered_log="$(mktemp)"
  if ! systemd-analyze verify packaging/systemd/*.service >"${systemd_log}" 2>&1; then
    # A clean CI runner intentionally has no deployed VPSGuard executables. Ignore
    # only those two exact diagnostics; every unit syntax or sandbox error remains
    # fatal. The ExecStart contracts below prevent a typo from being hidden.
    grep -Fv \
      -e 'Command /usr/local/bin/vps-guard-control is not executable: No such file or directory' \
      -e 'Command /usr/local/bin/vps-guard-edge is not executable: No such file or directory' \
      "${systemd_log}" >"${filtered_log}" || true
    if [[ -s "${filtered_log}" ]]; then
      cat "${filtered_log}" >&2
      rm -f "${systemd_log}" "${filtered_log}"
      exit 1
    fi
  fi
  rm -f "${systemd_log}" "${filtered_log}"
fi
grep -Fq 'ExecStart=/usr/local/bin/vps-guard-control' packaging/systemd/vps-guard-control.service
grep -Fq 'ExecStart=/usr/local/bin/vps-guard-edge' packaging/systemd/vps-guard-edge.service

echo "ops harness: PASS"
