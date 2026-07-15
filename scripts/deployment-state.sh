#!/usr/bin/env bash
set -euo pipefail

# OPS-002, OPS-005, OPS-009, SEC-001, TLS-005, ACT-010: VPSGuard가 소유하는
# 배포 상태만 snapshot·복구하고 기존 ingress·인증서·사이트 경계는 hash로 검증합니다.
mode="${1:---plan}"
snapshot_arg="${2:-}"
test_root="${VPS_GUARD_TEST_ROOT:-}"
snapshot_root="${VPS_GUARD_SNAPSHOT_ROOT:-/var/backups/vps-guard/deployments}"

owned_files=(
  /usr/local/bin/vps-guard
  /usr/local/bin/vps-guard-control
  /usr/local/bin/vps-guard-edge
  /usr/local/libexec/vps-guard/deployment-state
  /etc/systemd/system/vps-guard-control.service
  /etc/systemd/system/vps-guard-edge.service
  /etc/systemd/system/vps-guard-control.service.d/20-cloudflare-credential.conf
  /etc/systemd/system/vps-guard-control.service.d/20-service-credentials.conf
  /etc/systemd/system/vps-guard-control.service.d/30-tls-certificate.conf
  /etc/systemd/system/vps-guard-edge.service.d/30-tls-credentials.conf
  /usr/lib/tmpfiles.d/vps-guard.conf
  /etc/vps-guard/config.toml
  /etc/vps-guard/secrets/cloudflare-token
  /var/lib/vps-guard/ownership-manifest.txt
)

owned_directories=(
  /usr/local/libexec/vps-guard
  /etc/systemd/system/vps-guard-control.service.d
  /etc/systemd/system/vps-guard-edge.service.d
  /etc/vps-guard/secrets
  /etc/vps-guard
  /run/vps-guard
  /var/lib/vps-guard
)

vpsguard_services=(vps-guard-control.service vps-guard-edge.service)
protected_services=(
  nginx.service
  php8.5-fpm.service
  mysql.service
  redis-server.service
  g7-queue.service
  g7-scheduler.service
  g7-reverb.service
)

usage() {
  echo "usage: $0 [--plan|--snapshot|--verify SNAPSHOT|--restore SNAPSHOT]"
}

root_path() {
  printf '%s%s' "${test_root}" "$1"
}

require_runtime_authority() {
  if [[ -z "${test_root}" && "${EUID}" -ne 0 ]]; then
    echo "root is required for deployment snapshot and restore" >&2
    exit 2
  fi
  if [[ -n "${test_root}" && "${test_root}" != /* ]]; then
    echo "VPS_GUARD_TEST_ROOT must be absolute" >&2
    exit 2
  fi
}

hash_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

machine_id_hash() {
  local path
  path="$(root_path /etc/machine-id)"
  if [[ -f "${path}" ]]; then
    hash_file "${path}"
  elif [[ -n "${test_root}" ]]; then
    printf 'test-machine\n' | hash_stream
  else
    echo "missing"
  fi
}

service_state() {
  local unit="$1"
  local kind="$2"
  local state_file
  if [[ -n "${test_root}" ]]; then
    state_file="${test_root}/.vpsguard-test/systemd/${unit}.${kind}"
    if [[ -f "${state_file}" ]]; then
      sed -n '1p' "${state_file}"
    elif [[ "${kind}" == "enabled" ]]; then
      echo "not-found"
    else
      echo "inactive"
    fi
    return
  fi
  if [[ "${kind}" == "enabled" ]]; then
    systemctl is-enabled "${unit}" 2>/dev/null || true
  else
    systemctl is-active "${unit}" 2>/dev/null || true
  fi
}

set_service_state() {
  local unit="$1"
  local enabled="$2"
  local active="$3"
  local state_dir
  if [[ -n "${test_root}" ]]; then
    state_dir="${test_root}/.vpsguard-test/systemd"
    mkdir -p "${state_dir}"
    printf '%s\n' "${enabled}" >"${state_dir}/${unit}.enabled"
    printf '%s\n' "${active}" >"${state_dir}/${unit}.active"
    return
  fi

  case "${enabled}" in
    enabled|enabled-runtime|linked|linked-runtime|alias)
      systemctl enable "${unit}" >/dev/null
      ;;
    masked|masked-runtime)
      systemctl mask "${unit}" >/dev/null
      ;;
    disabled|indirect|static|generated|transient|not-found|"")
      systemctl disable "${unit}" >/dev/null 2>&1 || true
      ;;
    *)
      echo "unsupported saved enablement for ${unit}: ${enabled}" >&2
      exit 1
      ;;
  esac
  case "${active}" in
    active|activating|reloading)
      systemctl start "${unit}"
      ;;
    inactive|failed|deactivating|unknown|"")
      systemctl stop "${unit}" >/dev/null 2>&1 || true
      ;;
    *)
      echo "unsupported saved activity for ${unit}: ${active}" >&2
      exit 1
      ;;
  esac
}

normalized_activity() {
  case "$1" in
    active|activating|reloading) echo "up" ;;
    failed) echo "failed" ;;
    *) echo "down" ;;
  esac
}

account_exists() {
  if [[ -n "${test_root}" ]]; then
    [[ -f "${test_root}/.vpsguard-test/account-vps-guard" ]]
  else
    getent passwd vps-guard >/dev/null 2>&1
  fi
}

restore_account_absence() {
  local account_line uid home shell
  if ! account_exists; then
    return
  fi
  if [[ -n "${test_root}" ]]; then
    rm -f "${test_root}/.vpsguard-test/account-vps-guard"
    return
  fi
  account_line="$(getent passwd vps-guard)"
  IFS=: read -r _ _ uid _ _ home shell <<<"${account_line}"
  if [[ ! "${uid}" =~ ^[0-9]+$ || "${uid}" -ge 1000 || "${home}" != /var/lib/vps-guard ]]; then
    echo "refusing to remove a non-owned vps-guard account" >&2
    exit 1
  fi
  case "${shell}" in
    /usr/sbin/nologin|/sbin/nologin|/bin/false) ;;
    *) echo "refusing to remove vps-guard with unexpected shell" >&2; exit 1 ;;
  esac
  if pgrep -u vps-guard >/dev/null 2>&1; then
    echo "refusing to remove vps-guard while processes remain" >&2
    exit 1
  fi
  userdel vps-guard
  if getent group vps-guard >/dev/null 2>&1; then
    groupdel vps-guard
  fi
}

tree_hash() {
  local logical="$1"
  local source manifest file relative mode_value
  source="$(root_path "${logical}")"
  if [[ ! -e "${source}" ]]; then
    printf 'absent:%s\n' "${logical}" | hash_stream
    return
  fi
  manifest="$(mktemp)"
  while IFS= read -r file; do
    [[ -n "${file}" ]] || continue
    relative="${file#"${source}"/}"
    case "${logical}:${relative}" in
      /home/g7devops/public_html:storage/*|/home/g7devops/public_html:bootstrap/cache/*|/home/g7devops/public_html:.git/*)
        continue
        ;;
    esac
    if [[ -L "${file}" ]]; then
      printf 'link|%s|%s\n' "${relative}" "$(readlink "${file}")" >>"${manifest}"
    elif [[ -f "${file}" ]]; then
      mode_value="$(file_mode "${file}")"
      printf 'file|%s|%s|%s\n' "${relative}" "${mode_value}" "$(hash_file "${file}")" >>"${manifest}"
    fi
  done < <(find "${source}" \( -type f -o -type l \) -print | LC_ALL=C sort)
  hash_file "${manifest}"
  rm -f "${manifest}"
}

write_protected_state() {
  local output="$1"
  local unit
  {
    printf 'ssh|/etc/ssh|%s\n' "$(tree_hash /etc/ssh)"
    printf 'nginx|/etc/nginx|%s\n' "$(tree_hash /etc/nginx)"
    printf 'certificates|/etc/letsencrypt|%s\n' "$(tree_hash /etc/letsencrypt)"
    printf 'site|/home/g7devops/public_html|%s\n' "$(tree_hash /home/g7devops/public_html)"
    for unit in "${protected_services[@]}"; do
      printf 'service:%s|enabled=%s|activity=%s\n' \
        "${unit}" \
        "$(service_state "${unit}" enabled)" \
        "$(normalized_activity "$(service_state "${unit}" active)")"
    done
  } >"${output}"
}

write_listener_state() {
  local output="$1"
  local fixture_listeners
  if [[ -n "${test_root}" ]]; then
    fixture_listeners="${test_root}/.vpsguard-test/listeners"
    if [[ -f "${fixture_listeners}" ]]; then
      LC_ALL=C sort -u "${fixture_listeners}" >"${output}"
    else
      : >"${output}"
    fi
    return
  fi
  ss -H -ltn | awk '{print $4}' | grep -Ev ':(7727|18080)$' | LC_ALL=C sort -u >"${output}" || true
}

verify_snapshot_checksum() {
  local snapshot="$1"
  if [[ -L "${snapshot}" || ! -d "${snapshot}" || ! -f "${snapshot}/SHA256SUMS" ]]; then
    echo "snapshot directory or checksum is missing" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${snapshot}" && sha256sum --check --quiet SHA256SUMS)
  else
    (cd "${snapshot}" && shasum -a 256 --check SHA256SUMS >/dev/null)
  fi
}

validate_snapshot_path() {
  local snapshot="$1"
  [[ -n "${snapshot}" ]] || { echo "snapshot path is required" >&2; exit 2; }
  [[ "${snapshot}" == "${snapshot_root}"/deploy-* ]] || {
    echo "snapshot must be a direct child of ${snapshot_root}" >&2
    exit 2
  }
  [[ "$(dirname "${snapshot}")" == "${snapshot_root}" ]] || {
    echo "nested snapshot paths are rejected" >&2
    exit 2
  }
}

verify_machine() {
  local snapshot="$1"
  local expected current
  expected="$(awk -F '|' '$1 == "machine_id_sha256" { print $2 }' "${snapshot}/manifest.tsv")"
  current="$(machine_id_hash)"
  [[ -n "${expected}" && "${expected}" == "${current}" ]] || {
    echo "snapshot belongs to a different server" >&2
    exit 1
  }
}

verify_protected() {
  local snapshot="$1"
  local current missing
  current="$(mktemp)"
  write_protected_state "${current}"
  if ! cmp -s "${snapshot}/protected.tsv" "${current}"; then
    echo "protected SSH, Nginx, certificate, site or service state drifted" >&2
    rm -f "${current}"
    exit 1
  fi
  rm -f "${current}"

  current="$(mktemp)"
  write_listener_state "${current}"
  missing="$(comm -23 "${snapshot}/listeners.txt" "${current}")"
  rm -f "${current}"
  if [[ -n "${missing}" ]]; then
    echo "protected listener disappeared: ${missing}" >&2
    exit 1
  fi
}

create_snapshot() {
  local timestamp snapshot logical source destination unit directory state checksums
  require_runtime_authority
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  snapshot="${snapshot_root}/deploy-${timestamp}-$$"
  umask 077
  mkdir -p "${snapshot}/payload"
  chmod 0700 "${snapshot}" "${snapshot}/payload"
  {
    echo 'schema_version|1'
    echo "machine_id_sha256|$(machine_id_hash)"
    if account_exists; then
      echo 'account_vps_guard|present'
    else
      echo 'account_vps_guard|absent'
    fi
  } >"${snapshot}/manifest.tsv"
  : >"${snapshot}/absent-paths.txt"
  for logical in "${owned_files[@]}"; do
    source="$(root_path "${logical}")"
    if [[ -L "${source}" ]]; then
      echo "owned path must not be a symlink: ${logical}" >&2
      exit 1
    fi
    if [[ -f "${source}" ]]; then
      destination="${snapshot}/payload/${logical#/}"
      mkdir -p "$(dirname "${destination}")"
      cp -p "${source}" "${destination}"
    elif [[ -e "${source}" ]]; then
      echo "owned path is not a regular file: ${logical}" >&2
      exit 1
    else
      echo "${logical}" >>"${snapshot}/absent-paths.txt"
    fi
  done
  : >"${snapshot}/directory-state.tsv"
  for directory in "${owned_directories[@]}"; do
    if [[ -L "$(root_path "${directory}")" ]]; then
      echo "owned directory must not be a symlink: ${directory}" >&2
      exit 1
    elif [[ -d "$(root_path "${directory}")" ]]; then
      state=present
    else
      state=absent
    fi
    printf '%s|%s\n' "${directory}" "${state}" >>"${snapshot}/directory-state.tsv"
  done
  : >"${snapshot}/service-state.tsv"
  for unit in "${vpsguard_services[@]}"; do
    printf '%s|%s|%s\n' \
      "${unit}" \
      "$(service_state "${unit}" enabled)" \
      "$(service_state "${unit}" active)" >>"${snapshot}/service-state.tsv"
  done
  write_protected_state "${snapshot}/protected.tsv"
  write_listener_state "${snapshot}/listeners.txt"
  checksums="${snapshot}.SHA256SUMS.tmp"
  (
    cd "${snapshot}"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}"
      else
        shasum -a 256 "${file}"
      fi
    done >"${checksums}"
  )
  mv "${checksums}" "${snapshot}/SHA256SUMS"
  chmod -R go-rwx "${snapshot}"
  echo "snapshot=${snapshot}"
}

restore_snapshot() {
  local snapshot="$1"
  local logical source destination unit enabled active account_state directory state
  require_runtime_authority
  validate_snapshot_path "${snapshot}"
  [[ "${VPS_GUARD_RESTORE_CONFIRM:-}" == "restore-deployment-snapshot" ]] || {
    echo "VPS_GUARD_RESTORE_CONFIRM=restore-deployment-snapshot is required" >&2
    exit 2
  }
  verify_snapshot_checksum "${snapshot}"
  verify_machine "${snapshot}"

  while IFS='|' read -r unit enabled active; do
    [[ -n "${unit}" ]] || continue
    if [[ -n "${test_root}" ]]; then
      printf 'inactive\n' >"${test_root}/.vpsguard-test/systemd/${unit}.active"
    else
      systemctl stop "${unit}" >/dev/null 2>&1 || true
    fi
  done <"${snapshot}/service-state.tsv"

  while IFS= read -r logical; do
    [[ -n "${logical}" ]] || continue
    rm -f "$(root_path "${logical}")"
  done <"${snapshot}/absent-paths.txt"

  while IFS= read -r source; do
    [[ -n "${source}" ]] || continue
    logical="/${source#"${snapshot}/payload/"}"
    destination="$(root_path "${logical}")"
    if [[ -L "${destination}" || -L "$(dirname "${destination}")" ]]; then
      echo "refusing to restore through a symlink: ${logical}" >&2
      exit 1
    fi
    mkdir -p "$(dirname "${destination}")"
    rm -f "${destination}"
    cp -p "${source}" "${destination}"
  done < <(find "${snapshot}/payload" -type f -print | LC_ALL=C sort)

  if [[ -z "${test_root}" ]]; then
    systemctl daemon-reload
  fi
  while IFS='|' read -r unit enabled active; do
    [[ -n "${unit}" ]] || continue
    set_service_state "${unit}" "${enabled}" "${active}"
  done <"${snapshot}/service-state.tsv"

  while IFS='|' read -r directory state; do
    [[ "${state}" == "absent" ]] || continue
    rm -rf "$(root_path "${directory}")"
  done < <(LC_ALL=C sort -r "${snapshot}/directory-state.tsv")

  account_state="$(awk -F '|' '$1 == "account_vps_guard" { print $2 }' "${snapshot}/manifest.tsv")"
  if [[ "${account_state}" == "absent" ]]; then
    restore_account_absence
  elif [[ "${account_state}" != "present" ]]; then
    echo "invalid account state in snapshot" >&2
    exit 1
  fi

  verify_protected "${snapshot}"
  echo "restore=pass"
  echo "snapshot=${snapshot}"
}

case "${mode}" in
  --plan)
    usage
    echo "snapshot root: ${snapshot_root}"
    echo "restore scope: VPSGuard binary, unit, drop-in, config, token, service state and first-install directories"
    echo "protected: SSH, Nginx, certificates, G7 site and non-VPSGuard listeners"
    ;;
  --snapshot)
    create_snapshot
    ;;
  --verify)
    require_runtime_authority
    validate_snapshot_path "${snapshot_arg}"
    verify_snapshot_checksum "${snapshot_arg}"
    verify_machine "${snapshot_arg}"
    verify_protected "${snapshot_arg}"
    echo "protected=pass"
    echo "snapshot=${snapshot_arg}"
    ;;
  --restore)
    restore_snapshot "${snapshot_arg}"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
