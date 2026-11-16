#!/usr/bin/env bash
# Password reset smoke test, for a local stack whose user-service runs with
# ENVIRONMENT=development and no SMTP: it then logs the reset link instead of
# emailing it, and this script reads the link from that log.
#
#   1. register, 2. request a reset, 3. read the link from the log,
#   4. reset the password, 5. the link can't be used twice,
#   6. the old password fails and the new one works.
#
# Usage: BASE_URL=http://127.0.0.1:18080 USER_SERVICE_LOG=path/to/log scripts/test/reset-smoke.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
: "${USER_SERVICE_LOG:?set USER_SERVICE_LOG to the user-service log file}"
OLD_PW="${SMOKE_PASSWORD:-SmokeTest123!}"
NEW_PW="NewSmokeTest456!"
SUFFIX="$(date +%s)$$"
EMAIL="reset_${SUFFIX}@example.com"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "  ✗ $*"; exit 1; }
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }
json() { printf '{"%s":"%s","%s":"%s"}' "$1" "$2" "$3" "$4"; }

log "1/6 register"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d "{\"username\":\"reset_${SUFFIX}\",\"email\":\"$EMAIL\",\"password\":\"$OLD_PW\"}")" == 2* ]] \
  || fail "register failed"

log "2/6 request a reset"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/forgot-password" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\"}")" == 200 ]] || fail "forgot-password failed"

log "3/6 read the link from the log"
LINK=""
for _ in $(seq 1 20); do
  LINK="$(grep -o 'reset-password?token=[A-Za-z0-9_-]*' "$USER_SERVICE_LOG" | tail -1 || true)"
  [[ -n "$LINK" ]] && break
  sleep 0.5
done
[[ -n "$LINK" ]] || fail "no reset link was logged"
CODE="${LINK#*=}"
log "  ✓ got a reset link"

log "4/6 reset the password"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/reset-password" -H 'Content-Type: application/json' \
  -d "$(json token "$CODE" password "$NEW_PW")")" == 200 ]] || fail "reset failed"

log "5/6 the link can't be used twice"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/reset-password" -H 'Content-Type: application/json' \
  -d "$(json token "$CODE" password "Another789!x")")" == 400 ]] || fail "a used link worked again"

log "6/6 old password fails, new one works"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(json identifier "$EMAIL" password "$OLD_PW")")" == 401 ]] || fail "old password still works"
[[ "$(status -X POST "$BASE_URL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(json identifier "$EMAIL" password "$NEW_PW")")" == 200 ]] || fail "new password doesn't work"

log "RESET SMOKE TEST PASSED"
