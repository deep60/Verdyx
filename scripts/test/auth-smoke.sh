#!/usr/bin/env bash
# Auth-flow smoke test — validates the migrated auth path end-to-end through
# the API gateway (which proxies auth/identity to user-service).
#
# Unlike scripts/test/smoke.sh (which only checks health/readiness/metrics),
# this exercises the REAL user journey across the gateway <-> user-service
# boundary with a shared JWT:
#
#   1. register            (gateway -> user-service /auth/register)
#   2. login               (gateway -> user-service /auth/login)
#   3. verify / whoami      (gateway -> user-service /auth/me)  <-- proves the
#                            gateway accepts a token user-service minted
#   4. authenticated call   (GET /users/me on a strict-auth route)  <-- proves
#                            gateway middleware authorizes that same token
#   5-9. API keys           create one, use it (X-API-Key and Bearer), check
#                            it can't manage keys or the account or write
#                            outside its scopes, see it listed, revoke it
#
# Steps 3 and 4 are the ones that would break if the JWT contract or shared
# secret were wrong — i.e. the actual risk introduced by the auth migration.
#
# Usage:
#   scripts/test/auth-smoke.sh                     # against http://localhost:8080
#   BASE_URL=https://api.verdyx.com scripts/test/auth-smoke.sh
#
# Requires: curl. Uses jq if present, otherwise falls back to grep/sed.
# Exit code 0 on success, 1 on any failure.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PASSWORD="${SMOKE_PASSWORD:-SmokeTest123!}"   # meets gateway complexity rules
SUFFIX="$(date +%s)$$"
USERNAME="smoke_${SUFFIX}"
EMAIL="smoke_${SUFFIX}@example.com"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "  ✗ $*"; exit 1; }

# Extract a JSON string field. Prefer jq; fall back to a simple grep/sed.
json_get() {
  local key="$1" body="$2"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$body" | jq -r "$key // empty"
  else
    # crude fallback: matches "key":"value" for the leaf key name given as .foo.bar
    local leaf="${key##*.}"
    printf '%s' "$body" | grep -o "\"${leaf}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'
  fi
}

log "Target gateway: $BASE_URL"

# ── 1. Register ──────────────────────────────────────────────────
log "1/4 register  ($EMAIL)"
REG_BODY="$(curl -fsS --max-time 15 -X POST "$BASE_URL/api/v1/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" \
  || fail "register request failed (is the stack up? is user-service reachable?)"

TOKEN="$(json_get '.data.accessToken' "$REG_BODY")"
[[ -n "$TOKEN" ]] || fail "register returned no accessToken. Body: $REG_BODY"
log "  ✓ registered, got access token"

# ── 2. Login ─────────────────────────────────────────────────────
log "2/4 login"
LOGIN_BODY="$(curl -fsS --max-time 15 -X POST "$BASE_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"identifier\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" \
  || fail "login request failed"

LOGIN_TOKEN="$(json_get '.data.accessToken' "$LOGIN_BODY")"
[[ -n "$LOGIN_TOKEN" ]] || fail "login returned no accessToken. Body: $LOGIN_BODY"
TOKEN="$LOGIN_TOKEN"
log "  ✓ logged in"

# ── 3. Verify / whoami (gateway must accept user-service's token) ─
log "3/4 verify  (GET /auth/verify)"
VERIFY_BODY="$(curl -fsS --max-time 15 "$BASE_URL/api/v1/auth/verify" \
  -H "Authorization: Bearer $TOKEN")" \
  || fail "verify request failed — gateway did NOT accept the user-service token (JWT secret/claims mismatch?)"

VERIFY_EMAIL="$(json_get '.data.email' "$VERIFY_BODY")"
[[ "$VERIFY_EMAIL" == "$EMAIL" ]] \
  || fail "verify returned wrong/no email (got '$VERIFY_EMAIL'). Body: $VERIFY_BODY"
log "  ✓ verify resolved the current user via user-service"

# ── 4. Authenticated call on a strict-auth route ─────────────────
log "4/4 authenticated call  (GET /users/me)"
ME_BODY="$(curl -fsS --max-time 15 "$BASE_URL/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN")" \
  || fail "GET /users/me failed — strict auth middleware rejected the token"

ME_EMAIL="$(json_get '.email' "$ME_BODY")"
[[ "$ME_EMAIL" == "$EMAIL" ]] \
  || fail "/users/me returned wrong/no email (got '$ME_EMAIL'). Body: $ME_BODY"
log "  ✓ authenticated request accepted and proxied to user-service"

# ── 5-9. API keys ────────────────────────────────────────────────
# HTTP status of a request, without failing the script on 4xx.
status() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }

log "5/9 create an API key (read + scan)"
KEY_BODY="$(curl -fsS --max-time 15 -X POST "$BASE_URL/api/v1/auth/api-key" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"smoke","scopes":["read","scan"],"expires_in_days":1}')" \
  || fail "creating an API key failed"
API_KEY="$(json_get '.api_key' "$KEY_BODY")"
KEY_ID="$(json_get '.key_id' "$KEY_BODY")"
[[ "$API_KEY" == vdx_* ]] || fail "no vdx_ key returned. Body: $KEY_BODY"
log "  ✓ key created"

log "6/9 the key authenticates (X-API-Key and Bearer)"
ME_KEY="$(curl -fsS --max-time 15 "$BASE_URL/api/v1/users/me" -H "X-API-Key: $API_KEY")" \
  || fail "GET /users/me with X-API-Key failed"
[[ "$(json_get '.email' "$ME_KEY")" == "$EMAIL" ]] || fail "key resolved to the wrong user: $ME_KEY"
[[ "$(status "$BASE_URL/api/v1/users/me/stats" -H "Authorization: Bearer $API_KEY")" == 200 ]] \
  || fail "Bearer API key was not accepted on a strict route"
log "  ✓ key accepted both ways, as the right user"

log "7/9 the key stays within its limits"
[[ "$(status "$BASE_URL/api/v1/users/me/api-keys" -H "X-API-Key: $API_KEY")" == 403 ]] \
  || fail "a key could list keys"
[[ "$(status -X DELETE "$BASE_URL/api/v1/users/me" -H "X-API-Key: $API_KEY")" == 403 ]] \
  || fail "a key could delete the account"
[[ "$(status -X POST "$BASE_URL/api/v1/webhooks" -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' -d '{}')" == 403 ]] \
  || fail "a key without the write scope could create a webhook"
[[ "$(status "$BASE_URL/api/v1/users/me/stats" -H "X-API-Key: vdx_0000000000000000000000000000000000000000")" == 401 ]] \
  || fail "an unknown key was accepted"
log "  ✓ key management, account deletion and unscoped writes refused; unknown key rejected"

log "8/9 the owner sees the key, by prefix and last use"
LIST_BODY="$(curl -fsS --max-time 15 "$BASE_URL/api/v1/users/me/api-keys" -H "Authorization: Bearer $TOKEN")" \
  || fail "listing keys failed"
printf '%s' "$LIST_BODY" | grep -q "\"prefix\":\"${API_KEY:0:12}\"" || fail "key prefix missing from list: $LIST_BODY"
log "  ✓ listed with its prefix"

log "9/9 a revoked key stops working"
[[ "$(status -X DELETE "$BASE_URL/api/v1/users/me/api-keys/$KEY_ID" -H "Authorization: Bearer $TOKEN")" == 204 ]] \
  || fail "revoking the key failed"
[[ "$(status "$BASE_URL/api/v1/users/me/stats" -H "X-API-Key: $API_KEY")" == 401 ]] \
  || fail "a revoked key still works"
log "  ✓ revoked key rejected"

log "AUTH SMOKE TEST PASSED — register → login → verify → authenticated call → API keys all work end-to-end"
