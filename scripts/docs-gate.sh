#!/usr/bin/env bash
set -euo pipefail

status=0
while IFS= read -r file; do
  first_line=$(sed -n '1p' "$file")
  if [[ "$first_line" != '//!'* ]]; then
    echo "missing module rustdoc: $file"
    status=1
  fi
done < <(find crates -type f -name '*.rs' | sort)

exit "$status"
