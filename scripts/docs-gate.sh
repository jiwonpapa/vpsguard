#!/usr/bin/env bash
set -euo pipefail

workspace_manifest="Cargo.toml"
crate_root="crates"
status=0

if ! grep -Eq '^[[:space:]]*missing_docs[[:space:]]*=[[:space:]]*"deny"[[:space:]]*$' "${workspace_manifest}"; then
  echo "workspace missing_docs lint must be deny: ${workspace_manifest}"
  status=1
fi

while IFS= read -r manifest; do
  if ! awk '
    /^\[lints\]$/ { in_lints = 1; next }
    /^\[/ { in_lints = 0 }
    in_lints && /^[[:space:]]*workspace[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { found = 1 }
    END { exit found ? 0 : 1 }
  ' "${manifest}"; then
    echo "crate must inherit workspace lints: ${manifest}"
    status=1
  fi
done < <(find "${crate_root}" -mindepth 2 -maxdepth 2 -type f -name Cargo.toml | sort)

if grep -REn '#!?\[[[:space:]]*(allow|warn|expect)[[:space:]]*\([^]]*missing_docs' \
  "${crate_root}" --include='*.rs'; then
  echo "missing_docs lint downgrade is forbidden under ${crate_root}"
  status=1
fi

while IFS= read -r file; do
  first_line=$(sed -n '1p' "$file")
  if [[ "$first_line" != '//!'* ]]; then
    echo "missing module rustdoc: $file"
    status=1
  fi
done < <(find "${crate_root}" -type f -name '*.rs' | sort)

exit "$status"
