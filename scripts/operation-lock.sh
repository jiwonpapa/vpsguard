#!/usr/bin/env bash

# OPS-010: remote shell adapter의 critical section을 하나로 제한합니다.
# Rust transaction engine과 같은 operation ID를 사용하며 비밀값은 기록하지 않습니다.
operation_lock_backend=""
operation_lock_path=""
operation_lock_id=""

operation_lock_acquire() {
  local operation_id="$1"
  local lock_root="${VPS_GUARD_OPERATION_LOCK_ROOT:-/run/vps-guard}"
  local active="initializing"
  [[ "${operation_id}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || {
    echo "invalid operation lock ID" >&2
    return 2
  }
  mkdir -p "${lock_root}"
  chmod 0750 "${lock_root}" 2>/dev/null || true
  operation_lock_id="${operation_id}"
  if command -v flock >/dev/null 2>&1; then
    operation_lock_backend="flock"
    operation_lock_path="${lock_root}/operation.lock"
    # read/write open은 기존 holder의 operation ID를 먼저 지우지 않습니다.
    exec 9<>"${operation_lock_path}"
    if ! flock -n 9; then
      active="$(sed -n 's/^operation_id=//p' "${operation_lock_path}" 2>/dev/null | head -1)"
      [[ -n "${active}" ]] || active="initializing"
      echo "operation busy: active_operation_id=${active}" >&2
      exec 9>&-
      return 75
    fi
    {
      echo 'schema_version=1'
      echo "operation_id=${operation_id}"
      echo "pid=$$"
    } >"${operation_lock_path}"
    return
  fi

  operation_lock_backend="mkdir"
  operation_lock_path="${lock_root}/operation.lock.d"
  if ! mkdir "${operation_lock_path}" 2>/dev/null; then
    active="$(sed -n 's/^operation_id=//p' "${operation_lock_path}/record" 2>/dev/null | head -1)"
    [[ -n "${active}" ]] || active="initializing"
    echo "operation busy: active_operation_id=${active}" >&2
    return 75
  fi
  {
    echo 'schema_version=1'
    echo "operation_id=${operation_id}"
    echo "pid=$$"
  } >"${operation_lock_path}/record"
}

operation_lock_release() {
  case "${operation_lock_backend}" in
    flock)
      flock -u 9 2>/dev/null || true
      exec 9>&-
      ;;
    mkdir)
      rm -f "${operation_lock_path}/record"
      rmdir "${operation_lock_path}" 2>/dev/null || true
      ;;
    "") ;;
  esac
  operation_lock_backend=""
  operation_lock_path=""
}

operation_progress() {
  local phase="$1"
  local status="$2"
  printf 'operation_phase|%s|%s|%s|elapsed_seconds=%s\n' \
    "${operation_lock_id:-unlocked}" "${phase}" "${status}" "${SECONDS}"
}
