#!/usr/bin/env bash
# ACT-014/SEC-015: real PAM session으로 안전한 UFW add/read-back/remove를 검증합니다.
set -euo pipefail
umask 077

endpoint="${VPS_GUARD_ADMIN_URL:-https://192.168.0.143:7443}"
username="${VPS_GUARD_PAM_USER:-gnuboard5}"
response="$(mktemp)"
api_response="$(mktemp)"
cookie="$(mktemp)"
rule_id="vm_probe_$(date +%s)"
applied=0
csrf=""

cleanup() {
  if [[ "${applied}" == "1" && -n "${csrf}" ]]; then
    set +e
    cleanup_plan="$(api_post '/api/v1/firewall/plan' \
      "$(jq -nc --argjson rule "${rule}" '{kind:"remove",rule:$rule}')" 2>/dev/null)"
    cleanup_id="$(jq -er '.operation_id' <<<"${cleanup_plan}" 2>/dev/null)"
    api_post '/api/v1/firewall/apply' \
      "$(jq -nc --arg id "${cleanup_id}" '{operation_id:$id}')" >/dev/null 2>&1
  fi
  unset password token payload csrf
  rm -f "${response}" "${api_response}" "${cookie}"
}
trap cleanup EXIT

api_post() {
  local path="$1"
  local body="$2"
  local status
  status="$(curl --insecure --silent --show-error --output "${api_response}" \
    --write-out '%{http_code}' \
    --cookie "${cookie}" -H 'Content-Type: application/json' \
    -H "Origin: ${endpoint}" -H "X-CSRF-Token: ${csrf}" \
    --data "${body}" "${endpoint}${path}")"
  if [[ "${status}" -lt 200 || "${status}" -ge 300 ]]; then
    jq -c '{status:'"${status}"',error:.error.code,problem:.error.problem}' "${api_response}" >&2
    return 1
  fi
  cat "${api_response}"
}

read -r -s -p "PAM_PASSWORD:" password
printf '\n'
read -r -s -p "PAM_TOTP:" token
printf '\n'
[[ "${token}" =~ ^[0-9]{6}$ ]] || { echo "PAM_TOTP must be six ASCII digits" >&2; exit 2; }
payload="$(jq -nc --arg username "${username}" --arg password "${password}" \
  --arg token "${token}" '{username:$username,password:$password,totp_code:$token}')"
status="$(curl --insecure --silent --show-error --output "${response}" \
  --write-out '%{http_code}' --cookie-jar "${cookie}" \
  -H 'Content-Type: application/json' -H "Origin: ${endpoint}" \
  --data "${payload}" "${endpoint}/api/v1/session")"
[[ "${status}" == "200" ]]
csrf="$(jq -er '.csrf_token' "${response}")"
printf 'pam_session=PASS actor=%s method=%s\n' \
  "$(jq -r '.actor' "${response}")" "$(jq -r '.authentication_method' "${response}")"

firewall="$(curl --insecure --silent --show-error --fail-with-body \
  --cookie "${cookie}" "${endpoint}/api/v1/firewall")"
if ! jq -e '.mode == "standalone_ufw" and .backend == "ufw" and .mutable == true and .snapshot.active == true' \
  <<<"${firewall}" >/dev/null; then
  jq -c '{mode,backend,mutable,active:.snapshot.active,error:.error.code}' <<<"${firewall}"
  exit 1
fi
printf 'ufw_status=PASS active=true owned=%s foreign=%s\n' \
  "$(jq '.snapshot.owned_rules | length' <<<"${firewall}")" \
  "$(jq '.snapshot.foreign_rules | length' <<<"${firewall}")"

security="$(curl --insecure --silent --show-error --fail-with-body \
  --cookie "${cookie}" "${endpoint}/api/v1/status")"
jq -e '.inspection == "profiled" and .security.waf_mode == "tuned_enforce"' \
  <<<"${security}" >/dev/null
printf 'edge_security_status=PASS inspection=%s waf=%s\n' \
  "$(jq -r '.inspection' <<<"${security}")" "$(jq -r '.security.waf_mode' <<<"${security}")"

rule="$(jq -nc --arg id "${rule_id}" \
  '{id:$id,action:"deny",source:"192.0.2.1/32",destination_port:null,protocol:"any"}')"
add_plan="$(api_post '/api/v1/firewall/plan' "$(jq -nc --argjson rule "${rule}" '{kind:"add",rule:$rule}')")"
operation_id="$(jq -er '.operation_id' <<<"${add_plan}")"
api_post '/api/v1/firewall/apply' "$(jq -nc --arg id "${operation_id}" '{operation_id:$id}')" >/dev/null
applied=1

firewall="$(curl --insecure --silent --show-error --fail-with-body \
  --cookie "${cookie}" "${endpoint}/api/v1/firewall")"
jq -e --arg id "${rule_id}" '.snapshot.owned_rules | any(.id == $id)' <<<"${firewall}" >/dev/null
printf 'ufw_add_readback=PASS rule=%s\n' "${rule_id}"

remove_plan="$(api_post '/api/v1/firewall/plan' "$(jq -nc --argjson rule "${rule}" '{kind:"remove",rule:$rule}')")"
operation_id="$(jq -er '.operation_id' <<<"${remove_plan}")"
api_post '/api/v1/firewall/apply' "$(jq -nc --arg id "${operation_id}" '{operation_id:$id}')" >/dev/null
applied=0

firewall="$(curl --insecure --silent --show-error --fail-with-body \
  --cookie "${cookie}" "${endpoint}/api/v1/firewall")"
jq -e --arg id "${rule_id}" '.snapshot.owned_rules | all(.id != $id)' <<<"${firewall}" >/dev/null
printf 'ufw_remove_readback=PASS rule=%s\n' "${rule_id}"
printf 'standalone_security_probe=PASS\n'
