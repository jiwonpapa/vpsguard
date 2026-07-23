#!/usr/bin/env bash
set -euo pipefail

# OPS-010: 두 번째 apply·restore process는 active operation ID와 함께 거부됩니다.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'operation_lock_release; rm -rf "${fixture}"' EXIT

# shellcheck source=scripts/operation-lock.sh
source "${repo_root}/scripts/operation-lock.sh"
VPS_GUARD_OPERATION_LOCK_ROOT="${fixture}" operation_lock_acquire fixture-first
if VPS_GUARD_OPERATION_LOCK_ROOT="${fixture}" bash -c \
  'source "$1"; operation_lock_acquire fixture-second' _ \
  "${repo_root}/scripts/operation-lock.sh" >/dev/null 2>"${fixture}/busy.err"; then
  echo "concurrent operation lock was accepted" >&2
  exit 1
fi
grep -Fq 'active_operation_id=fixture-first' "${fixture}/busy.err"
operation_lock_release

VPS_GUARD_OPERATION_LOCK_ROOT="${fixture}" bash -c \
  'source "$1"; operation_lock_acquire fixture-second; operation_lock_release' _ \
  "${repo_root}/scripts/operation-lock.sh"

echo "operation lock harness: PASS"
