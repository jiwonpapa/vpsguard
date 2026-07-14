#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

contract_ids="$(mktemp)"
trace_ids="$(mktemp)"
trap 'rm -f "${contract_ids}" "${trace_ids}"' EXIT

rg -o '\b(EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}\b' \
  specs/product/06-requirements-contracts.md | sort -u >"${contract_ids}"
rg -o '\b(EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}\b' \
  specs/product/07-verification-traceability.md | sort -u >"${trace_ids}"

missing="$(comm -23 "${contract_ids}" "${trace_ids}")"
extra="$(comm -13 "${contract_ids}" "${trace_ids}")"
if [[ -n "${missing}" || -n "${extra}" ]]; then
  [[ -z "${missing}" ]] || printf 'requirements missing from traceability:\n%s\n' "${missing}" >&2
  [[ -z "${extra}" ]] || printf 'unknown requirements in traceability:\n%s\n' "${extra}" >&2
  exit 1
fi

count="$(wc -l <"${contract_ids}" | tr -d ' ')"
[[ "${count}" == "82" ]] || {
  echo "unexpected requirement count: ${count}" >&2
  exit 1
}

echo "requirements gate: PASS (${count} IDs)"
