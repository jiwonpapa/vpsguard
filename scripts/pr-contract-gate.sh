#!/usr/bin/env bash
set -euo pipefail

[[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]] || exit 0
[[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]] || {
  echo "GITHUB_EVENT_PATH is required for pull_request" >&2
  exit 1
}

body="$(jq -r '.pull_request.body // ""' "${GITHUB_EVENT_PATH}")"
if ! rg -q '\b(EDGE|OBS|DET|ACT|TLS|UI|OPS|SEC|NFR)-[0-9]{3}\b' <<<"${body}"; then
  echo "pull request body must include at least one requirement ID" >&2
  exit 1
fi

echo "PR contract gate: PASS"
