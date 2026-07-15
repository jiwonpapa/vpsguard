#!/usr/bin/env bash
set -euo pipefail

# OPS-002, OPS-003, OPS-005, OPS-009, TLS-005: g7devops public ingress의
# Nginx·VPSGuard 설정, service 상태와 VPSGuard-owned hook을 checksum snapshot으로
# 보존하고 성공한 direct TLS 전환도 별도 명령으로 되돌립니다.
mode="${1:---plan}"
snapshot_arg="${2:-}"
test_root="${VPS_GUARD_TEST_ROOT:-}"
snapshot_root="${VPS_GUARD_DIRECT_SNAPSHOT_ROOT:-/var/backups/vps-guard/ingress}"

active_nginx="/etc/nginx/sites-available/g7.conf"
active_config="/etc/vps-guard/config.toml"
dropin="/etc/systemd/system/vps-guard-edge.service.d/30-g7devops-tls.conf"
default_deny="/etc/nginx/sites-enabled/g7-default-deny.conf"
expected_default_deny_target="/etc/nginx/sites-available/g7-default-deny.conf"
generic_certbot_hook="/usr/local/libexec/vps-guard/certbot-deploy-hook"
site_certbot_hook="/etc/letsencrypt/renewal-hooks/deploy/vps-guard"
certificate="/etc/letsencrypt/live/g7devops.com/fullchain.pem"
public_url="${VPS_GUARD_PUBLIC_PROBE_URL:-https://www.g7devops.com/}"

usage() {
  echo "usage: $0 --plan | --snapshot [direct|rollback] | --verify SNAPSHOT | --restore SNAPSHOT"
}

root_path() {
  printf '%s%s' "${test_root}" "$1"
}

require_authority() {
  if [[ -z "${test_root}" && "${EUID}" -ne 0 ]]; then
    echo "root is required for direct ingress state" >&2
    exit 2
  fi
  if [[ -n "${test_root}" && "${test_root}" != /* ]]; then
    echo "VPS_GUARD_TEST_ROOT must be absolute" >&2
    exit 2
  fi
  [[ "${snapshot_root}" == /* ]] || {
    echo "snapshot root must be absolute" >&2
    exit 2
  }
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

machine_id_hash() {
  local path
  path="$(root_path /etc/machine-id)"
  if [[ -f "${path}" ]]; then
    hash_file "${path}"
  elif [[ -n "${test_root}" ]]; then
    printf 'test-machine\n' | if command -v sha256sum >/dev/null 2>&1; then
      sha256sum | awk '{print $1}'
    else
      shasum -a 256 | awk '{print $1}'
    fi
  else
    echo "missing"
  fi
}

service_state() {
  local unit="$1"
  local kind="$2"
  local state_file
  if [[ -n "${test_root}" ]]; then
    state_file="${VPS_GUARD_FAKE_STATE_DIR:?}/${unit}.${kind}"
    if [[ -f "${state_file}" ]]; then
      sed -n '1p' "${state_file}"
    elif [[ "${kind}" == "enabled" ]]; then
      echo "disabled"
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

set_enabled_state() {
  local unit="$1"
  local desired="$2"
  if [[ -n "${test_root}" ]]; then
    printf '%s\n' "${desired}" >"${VPS_GUARD_FAKE_STATE_DIR:?}/${unit}.enabled"
    return
  fi
  case "${desired}" in
    enabled|enabled-runtime|linked|linked-runtime|alias)
      systemctl enable "${unit}" >/dev/null
      ;;
    disabled|indirect|static|generated|transient|not-found|"")
      systemctl disable "${unit}" >/dev/null 2>&1 || true
      ;;
    *)
      echo "unsupported saved enablement for ${unit}: ${desired}" >&2
      return 1
      ;;
  esac
}

set_active_state() {
  local unit="$1"
  local desired="$2"
  if [[ -n "${test_root}" ]]; then
    case "${desired}" in
      active|activating|reloading) desired=active ;;
      *) desired=inactive ;;
    esac
    printf '%s\n' "${desired}" >"${VPS_GUARD_FAKE_STATE_DIR:?}/${unit}.active"
    return
  fi
  case "${desired}" in
    active|activating|reloading) systemctl start "${unit}" ;;
    inactive|failed|deactivating|unknown|"") systemctl stop "${unit}" >/dev/null 2>&1 || true ;;
    *)
      echo "unsupported saved activity for ${unit}: ${desired}" >&2
      return 1
      ;;
  esac
}

manifest_value() {
  local snapshot="$1"
  local key="$2"
  awk -F '|' -v key="${key}" '$1 == key { print $2 }' "${snapshot}/manifest.tsv"
}

copy_optional() {
  local logical="$1"
  local destination="$2"
  local source
  source="$(root_path "${logical}")"
  if [[ -L "${source}" ]]; then
    echo "optional state path must not be a symlink: ${logical}" >&2
    return 1
  fi
  if [[ -f "${source}" ]]; then
    install -m "$(stat -c '%a' "${source}")" "${source}" "${destination}"
    echo "present"
  elif [[ -e "${source}" ]]; then
    echo "optional state path is not a regular file: ${logical}" >&2
    return 1
  else
    echo "absent"
  fi
}

public_edge_header_state() {
  local headers
  if [[ -n "${test_root}" ]]; then
    echo "${VPS_GUARD_TEST_PUBLIC_EDGE_HEADER:-absent}"
    return
  fi
  headers="$(mktemp)"
  if ! curl --fail --silent --show-error --max-time 15 \
    --dump-header "${headers}" --output /dev/null "${public_url}"; then
    rm -f "${headers}"
    return 1
  fi
  if grep -Eiq '^x-vps-guard:[[:space:]]*guard-edge' "${headers}"; then
    echo "present"
  else
    echo "absent"
  fi
  rm -f "${headers}"
}

edge_public_state() {
  if [[ -n "${test_root}" ]]; then
    echo "${VPS_GUARD_TEST_EDGE_PUBLIC:-false}"
  elif ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):443.*vps-guard-edge'; then
    echo "true"
  else
    echo "false"
  fi
}

certificate_fingerprint() {
  if [[ -n "${test_root}" ]]; then
    echo "test-certificate"
  else
    openssl x509 -in "$(root_path "${certificate}")" -noout -fingerprint -sha256
  fi
}

write_checksums() {
  local snapshot="$1"
  local temporary="${snapshot}.SHA256SUMS.tmp"
  (
    cd "${snapshot}"
    find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | while IFS= read -r file; do
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}"
      else
        shasum -a 256 "${file}"
      fi
    done >"${temporary}"
  )
  mv "${temporary}" "${snapshot}/SHA256SUMS"
}

verify_checksums() {
  local snapshot="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${snapshot}" && sha256sum --check --quiet SHA256SUMS)
  else
    (cd "${snapshot}" && shasum -a 256 --check SHA256SUMS >/dev/null)
  fi
}

validate_snapshot() {
  local snapshot="$1"
  [[ -n "${snapshot}" ]] || { echo "snapshot path is required" >&2; return 1; }
  [[ "${snapshot}" == "${snapshot_root}"/direct-* ]] || {
    echo "snapshot must be a direct child of ${snapshot_root}" >&2
    return 1
  }
  [[ "$(dirname "${snapshot}")" == "${snapshot_root}" && ! -L "${snapshot}" && -d "${snapshot}" ]] || {
    echo "invalid direct snapshot path" >&2
    return 1
  }
  [[ -f "${snapshot}/manifest.tsv" && -f "${snapshot}/SHA256SUMS" ]] || {
    echo "direct snapshot metadata is missing" >&2
    return 1
  }
  verify_checksums "${snapshot}"
  [[ "$(manifest_value "${snapshot}" schema_version)" == "1" ]]
  [[ "$(manifest_value "${snapshot}" machine_id_sha256)" == "$(machine_id_hash)" ]] || {
    echo "snapshot belongs to a different server" >&2
    return 1
  }
  [[ -f "${snapshot}/g7.conf" && -f "${snapshot}/config.toml" ]]
}

create_snapshot() {
  local label="${1:-direct}"
  local timestamp snapshot nginx_source config_source default_state default_target
  local dropin_state generic_hook_state site_hook_state
  [[ "${label}" == "direct" || "${label}" == "rollback" ]] || {
    echo "invalid direct snapshot label" >&2
    return 1
  }
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  snapshot="${snapshot_root}/direct-${timestamp}-$$-${label}"
  umask 077
  mkdir -p "${snapshot_root}" "${snapshot}"
  chmod 0700 "${snapshot_root}" "${snapshot}"
  nginx_source="$(root_path "${active_nginx}")"
  config_source="$(root_path "${active_config}")"
  [[ -f "${nginx_source}" && ! -L "${nginx_source}" ]]
  [[ -f "${config_source}" && ! -L "${config_source}" ]]
  install -m 0644 "${nginx_source}" "${snapshot}/g7.conf"
  install -m 0640 "${config_source}" "${snapshot}/config.toml"
  dropin_state="$(copy_optional "${dropin}" "${snapshot}/edge-tls.conf")"
  generic_hook_state="$(copy_optional "${generic_certbot_hook}" "${snapshot}/certbot-deploy-hook")"
  site_hook_state="$(copy_optional "${site_certbot_hook}" "${snapshot}/g7-certbot-deploy-hook")"
  default_state="absent"
  default_target=""
  if [[ -L "$(root_path "${default_deny}")" ]]; then
    default_state="present"
    default_target="$(readlink "$(root_path "${default_deny}")")"
    [[ "${default_target}" == "${expected_default_deny_target}" ]] || {
      echo "unexpected default deny symlink target" >&2
      return 1
    }
  elif [[ -e "$(root_path "${default_deny}")" ]]; then
    echo "default deny path must be a symlink or absent" >&2
    return 1
  fi
  {
    echo 'schema_version|1'
    echo "machine_id_sha256|$(machine_id_hash)"
    echo "label|${label}"
    echo "dropin|${dropin_state}"
    echo "default_deny|${default_state}"
    echo "default_deny_target|${default_target}"
    echo "generic_certbot_hook|${generic_hook_state}"
    echo "site_certbot_hook|${site_hook_state}"
    echo "edge_enabled|$(service_state vps-guard-edge.service enabled)"
    echo "edge_active|$(service_state vps-guard-edge.service active)"
    echo "nginx_enabled|$(service_state nginx.service enabled)"
    echo "nginx_active|$(service_state nginx.service active)"
    echo "edge_public|$(edge_public_state)"
    echo "public_edge_header|$(public_edge_header_state)"
    echo "certificate_fingerprint|$(certificate_fingerprint)"
  } >"${snapshot}/manifest.tsv"
  write_checksums "${snapshot}"
  chmod -R go-rwx "${snapshot}"
  echo "snapshot=${snapshot}"
}

restore_optional() {
  local snapshot="$1"
  local key="$2"
  local source_name="$3"
  local logical="$4"
  local mode_value="$5"
  local state destination
  state="$(manifest_value "${snapshot}" "${key}")"
  destination="$(root_path "${logical}")"
  case "${state}" in
    present)
      [[ -f "${snapshot}/${source_name}" && ! -L "${snapshot}/${source_name}" ]]
      install -d -m 0755 "$(dirname "${destination}")"
      install -m "${mode_value}" "${snapshot}/${source_name}" "${destination}"
      ;;
    absent) rm -f "${destination}" ;;
    *) echo "invalid ${key} state" >&2; return 1 ;;
  esac
}

preflight_snapshot() {
  local snapshot="$1"
  local test_config
  if [[ -n "${test_root}" ]]; then
    return
  fi
  /usr/local/bin/vps-guard check-config --config "${snapshot}/config.toml" >/dev/null
  test_config="$(mktemp /etc/nginx/vpsguard-direct-restore.XXXXXX.conf)"
  trap 'rm -f "${test_config}"' RETURN
  awk -v candidate="${snapshot}/g7.conf" '
    $1 == "include" && $2 == "/etc/nginx/sites-enabled/*;" {
      print "\tinclude " candidate ";"
      replaced = 1
      next
    }
    { print }
    END { exit replaced ? 0 : 1 }
  ' /etc/nginx/nginx.conf >"${test_config}"
  nginx -t -p /etc/nginx/ -c "${test_config}" >/dev/null
  rm -f "${test_config}"
  trap - RETURN
}

apply_snapshot() {
  local snapshot="$1"
  local edge_enabled edge_active nginx_enabled nginx_active edge_public expected_header
  local cutover_seconds=0
  validate_snapshot "${snapshot}"
  preflight_snapshot "${snapshot}"
  edge_enabled="$(manifest_value "${snapshot}" edge_enabled)"
  edge_active="$(manifest_value "${snapshot}" edge_active)"
  nginx_enabled="$(manifest_value "${snapshot}" nginx_enabled)"
  nginx_active="$(manifest_value "${snapshot}" nginx_active)"
  edge_public="$(manifest_value "${snapshot}" edge_public)"
  expected_header="$(manifest_value "${snapshot}" public_edge_header)"
  [[ "${edge_public}" == "true" || "${edge_public}" == "false" ]]
  [[ "${expected_header}" == "present" || "${expected_header}" == "absent" ]]
  if [[ "${edge_public}" == "true" ]]; then
    [[ "${edge_active}" =~ ^(active|activating|reloading)$ ]] || {
      echo "edge-public snapshot requires an active edge service" >&2
      return 1
    }
  else
    [[ "${nginx_active}" =~ ^(active|activating|reloading)$ ]] || {
      echo "nginx-public snapshot requires an active Nginx service" >&2
      return 1
    }
  fi

  # 파일과 후보 검증은 현재 public ingress가 살아 있는 동안 끝냅니다.
  install -d -m 0755 "$(dirname "$(root_path "${active_nginx}")")" \
    "$(dirname "$(root_path "${active_config}")")"
  install -m 0644 "${snapshot}/g7.conf" "$(root_path "${active_nginx}")"
  install -m 0640 "${snapshot}/config.toml" "$(root_path "${active_config}")"
  restore_optional "${snapshot}" dropin edge-tls.conf "${dropin}" 0644
  restore_optional "${snapshot}" generic_certbot_hook certbot-deploy-hook "${generic_certbot_hook}" 0755
  restore_optional "${snapshot}" site_certbot_hook g7-certbot-deploy-hook "${site_certbot_hook}" 0755
  case "$(manifest_value "${snapshot}" default_deny)" in
    present)
      [[ "$(manifest_value "${snapshot}" default_deny_target)" == "${expected_default_deny_target}" ]]
      install -d -m 0755 "$(dirname "$(root_path "${default_deny}")")"
      ln -sfn "${expected_default_deny_target}" "$(root_path "${default_deny}")"
      ;;
    absent) rm -f "$(root_path "${default_deny}")" ;;
    *) echo "invalid default deny state" >&2; return 1 ;;
  esac

  set_enabled_state vps-guard-edge.service "${edge_enabled}"
  set_enabled_state nginx.service "${nginx_enabled}"
  if [[ -z "${test_root}" ]]; then
    systemctl daemon-reload
    /usr/local/bin/vps-guard check-config --config "$(root_path "${active_config}")" >/dev/null
    nginx -t >/dev/null
  fi
  if [[ -n "${test_root}" ]]; then
    set_active_state vps-guard-edge.service "${edge_active}"
    set_active_state nginx.service "${nginx_active}"
    cutover_seconds="${VPS_GUARD_TEST_CUTOVER_SECONDS:-0}"
  else
    local cutover_started
    cutover_started="${SECONDS}"
    # public 80/443 전환 구간입니다. 다른 파일 copy·checksum·configtest는 이 전에 끝났습니다.
    systemctl stop vps-guard-edge.service >/dev/null 2>&1 || true
    case "${nginx_active}" in
      active|activating|reloading) systemctl restart nginx.service ;;
      inactive|failed|deactivating|unknown|"") systemctl stop nginx.service >/dev/null 2>&1 || true ;;
      *) echo "unsupported saved activity for nginx.service: ${nginx_active}" >&2; return 1 ;;
    esac
    case "${edge_active}" in
      active|activating|reloading) systemctl start vps-guard-edge.service ;;
      inactive|failed|deactivating|unknown|"") ;;
      *) echo "unsupported saved activity for vps-guard-edge.service: ${edge_active}" >&2; return 1 ;;
    esac
    cutover_seconds=$((SECONDS - cutover_started))
  fi
  if (( cutover_seconds > 5 )); then
    echo "public ingress cutover exceeded 5 seconds: ${cutover_seconds}s" >&2
    return 1
  fi

  if [[ -z "${test_root}" ]]; then
    local headers served_fingerprint file_fingerprint
    headers="$(mktemp)"
    curl --fail --silent --show-error --retry 40 --retry-connrefused --retry-delay 0 \
      --max-time 15 --dump-header "${headers}" --output /dev/null "${public_url}"
    if grep -Eiq '^x-vps-guard:[[:space:]]*guard-edge' "${headers}"; then
      [[ "${expected_header}" == "present" ]]
    else
      [[ "${expected_header}" == "absent" ]]
    fi
    rm -f "${headers}"
    file_fingerprint="$(openssl x509 -in "$(root_path "${certificate}")" -noout -fingerprint -sha256)"
    served_fingerprint="$(openssl s_client -connect 127.0.0.1:443 -servername www.g7devops.com </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
    [[ "${served_fingerprint}" == "${file_fingerprint}" ]]
    if [[ "${edge_public}" == "true" ]]; then
      ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):443.*vps-guard-edge'
    else
      ss -H -ltnp | grep -Eq '(0\.0\.0\.0|\*):443.*nginx'
    fi
  fi
}

restore_snapshot() {
  local snapshot="$1"
  local rollback_output rollback rc
  [[ "${VPS_GUARD_DIRECT_RESTORE_CONFIRM:-}" == "restore-direct-snapshot" ]] || {
    echo "VPS_GUARD_DIRECT_RESTORE_CONFIRM=restore-direct-snapshot is required" >&2
    return 2
  }
  validate_snapshot "${snapshot}"
  rollback_output="$(create_snapshot rollback)"
  rollback="${rollback_output#snapshot=}"
  rollback_on_error() {
    rc=$?
    [[ ${rc} -eq 0 ]] && return
    trap - EXIT
    echo "direct restore failed; restoring pre-attempt state" >&2
    VPS_GUARD_TEST_CUTOVER_SECONDS=0 apply_snapshot "${rollback}" || \
      echo "direct restore rollback failed: ${rollback}" >&2
    exit "${rc}"
  }
  trap rollback_on_error EXIT
  apply_snapshot "${snapshot}"
  trap - EXIT
  echo "restore=pass"
  echo "snapshot=${snapshot}"
  echo "rollback=${rollback}"
}

require_authority
case "${mode}" in
  --plan)
    echo "snapshot root: ${snapshot_root}"
    echo "scope: Nginx ingress, VPSGuard config/drop-in, service state and Certbot hooks"
    echo "replacement: stop edge and Nginx, restore exact state, then restart in saved topology order"
    ;;
  --snapshot)
    create_snapshot "${snapshot_arg:-direct}"
    ;;
  --verify)
    validate_snapshot "${snapshot_arg}"
    echo "verify=pass"
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
