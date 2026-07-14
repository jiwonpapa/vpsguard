#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

contract_ids="$(mktemp)"
trace_ids="$(mktemp)"
registry_ids="$(mktemp)"
trap 'rm -f "${contract_ids}" "${trace_ids}" "${registry_ids}"' EXIT

mode="${1:---development}"
case "${mode}" in
  --development|--release) ;;
  *) echo "usage: $0 [--development|--release]" >&2; exit 2 ;;
esac

grep -Eo '(EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}' \
  specs/product/06-requirements-contracts.md | sort -u >"${contract_ids}"
grep -Eo '(EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}' \
  specs/product/07-verification-traceability.md | sort -u >"${trace_ids}"
awk -F '|' '!/^#/ && NF { print $1 }' specs/product/verification-status.tsv | sort >"${registry_ids}"

missing="$(comm -23 "${contract_ids}" "${trace_ids}")"
extra="$(comm -13 "${contract_ids}" "${trace_ids}")"
if [[ -n "${missing}" || -n "${extra}" ]]; then
  [[ -z "${missing}" ]] || printf 'requirements missing from traceability:\n%s\n' "${missing}" >&2
  [[ -z "${extra}" ]] || printf 'unknown requirements in traceability:\n%s\n' "${extra}" >&2
  exit 1
fi

duplicate_registry_ids="$(uniq -d "${registry_ids}")"
if [[ -n "${duplicate_registry_ids}" ]]; then
  printf 'duplicate requirements in verification status:\n%s\n' "${duplicate_registry_ids}" >&2
  exit 1
fi

missing_registry="$(comm -23 "${contract_ids}" "${registry_ids}")"
extra_registry="$(comm -13 "${contract_ids}" "${registry_ids}")"
if [[ -n "${missing_registry}" || -n "${extra_registry}" ]]; then
  [[ -z "${missing_registry}" ]] || printf 'requirements missing from verification status:\n%s\n' "${missing_registry}" >&2
  [[ -z "${extra_registry}" ]] || printf 'unknown requirements in verification status:\n%s\n' "${extra_registry}" >&2
  exit 1
fi

while IFS='|' read -r requirement status implementation automated operational extra; do
  [[ -z "${requirement}" || "${requirement}" == \#* ]] && continue
  [[ -z "${extra:-}" ]] || { echo "too many fields for ${requirement}" >&2; exit 1; }
  case "${status}" in
    PLANNED)
      [[ "${implementation}" == "-" && "${automated}" == "-" && "${operational}" == "-" ]] || {
        echo "PLANNED requirement must not claim evidence: ${requirement}" >&2
        exit 1
      }
      ;;
    CODE_ONLY|AUTO_PASS|VPS_PASS)
      [[ "${implementation}" != "-" && -e "${implementation}" ]] || {
        echo "missing implementation evidence for ${requirement}: ${implementation}" >&2
        exit 1
      }
      ;;
    *) echo "unknown verification status for ${requirement}: ${status}" >&2; exit 1 ;;
  esac
  if [[ "${status}" == "AUTO_PASS" || "${status}" == "VPS_PASS" ]]; then
    [[ "${automated}" != "-" && -e "${automated}" ]] || {
      echo "missing automated evidence for ${requirement}: ${automated}" >&2
      exit 1
    }
  fi
  if [[ "${status}" == "VPS_PASS" ]]; then
    [[ "${operational}" != "-" && -e "${operational}" ]] || {
      echo "missing operational evidence for ${requirement}: ${operational}" >&2
      exit 1
    }
  fi
done <specs/product/verification-status.tsv

count="$(wc -l <"${contract_ids}" | tr -d ' ')"
planned="$(awk -F '|' '$2 == "PLANNED" { count++ } END { print count + 0 }' specs/product/verification-status.tsv)"
code_only="$(awk -F '|' '$2 == "CODE_ONLY" { count++ } END { print count + 0 }' specs/product/verification-status.tsv)"
auto_pass="$(awk -F '|' '$2 == "AUTO_PASS" { count++ } END { print count + 0 }' specs/product/verification-status.tsv)"
vps_pass="$(awk -F '|' '$2 == "VPS_PASS" { count++ } END { print count + 0 }' specs/product/verification-status.tsv)"

if [[ "${mode}" == "--release" && $((planned + code_only)) -gt 0 ]]; then
  echo "release gate blocked: PLANNED=${planned}, CODE_ONLY=${code_only}, AUTO_PASS=${auto_pass}, VPS_PASS=${vps_pass}" >&2
  exit 1
fi

echo "requirements gate: PASS (${count} IDs; PLANNED=${planned}, CODE_ONLY=${code_only}, AUTO_PASS=${auto_pass}, VPS_PASS=${vps_pass})"
