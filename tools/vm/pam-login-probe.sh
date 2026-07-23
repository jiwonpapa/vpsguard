#!/usr/bin/env bash
# SEC-015: exercise the real PAM password + TOTP browser session without logging credentials.
set -euo pipefail
umask 077
endpoint="${VPS_GUARD_ADMIN_URL:-https://192.168.0.143:7443}"
username="${VPS_GUARD_PAM_USER:-gnuboard5}"
response="$(mktemp)"
cookie="$(mktemp)"
cleanup() {
  unset password token payload
  rm -f "${response}" "${cookie}"
}
trap cleanup EXIT
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
printf 'pam_login_http=%s\n' "${status}"
if [[ "${status}" != "200" ]]; then
  jq -c '{error:.error.code}' "${response}"
  exit 1
fi
jq -c '{actor,authentication_method,expires_in_seconds}' "${response}"
