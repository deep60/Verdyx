#!/usr/bin/env bash
# Teams smoke test, through the API gateway. Creates four throwaway accounts
# (ana, ben, cy, dan) and checks who can see and do what:
#
#   1. ana creates a team and invites ben (member) and cy (viewer)
#   2. invitation links only work for the address they were sent to, and an
#      unverified address can't accept from the list without the link
#   3. a scan saved to the team is visible to members, not to outsiders;
#      viewers can't scan into the team
#   4. team API keys: scans land in the team, the key reads only team scans,
#      can't touch the account, and stops when its maker loses admin rights
#   5. role rules: the last owner can't leave; removal cuts access at once
#   6. deleting the team hands scans back to their uploaders
#   7. deleting an account hands a team it alone owned to its next admin, and
#      keeps the scans it saved to the team
#
# Usage:  BASE_URL=http://localhost:8080 scripts/test/teams-smoke.sh
# Requires: curl, jq. Exit code 0 on success.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="$BASE_URL/api/v1"
PASSWORD="${SMOKE_PASSWORD:-SmokeTest123!}"
SUFFIX="$(date +%s)$$"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "  ✗ $*"; exit 1; }
ok()   { log "  ✓ $*"; }

# req METHOD PATH AUTH [JSON] -> sets STATUS and BODY. AUTH is "Bearer x",
# "key:<api key>" or "-".
req() {
  local method="$1" path="$2" auth="$3" data="${4:-}" args=()
  case "$auth" in
    -) ;;
    key:*) args+=(-H "X-API-Key: ${auth#key:}") ;;
    *) args+=(-H "Authorization: $auth") ;;
  esac
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data "$data")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -w '%{http_code}' -X "$method" "${args[@]}" "$API$path")"
  BODY="$(cat "$TMP/body")"
}
expect() { # expect STATUS what
  [[ "$STATUS" == "$1" ]] || fail "$2: expected $1, got $STATUS. Body: $BODY"
  ok "$2 ($STATUS)"
}

# Upload a URL scan as multipart. upload AUTH URL [TEAM_ID]
upload() {
  local auth="$1" url="$2" team="${3:-}" args=()
  case "$auth" in
    key:*) args+=(-H "X-API-Key: ${auth#key:}") ;;
    *) args+=(-H "Authorization: $auth") ;;
  esac
  [[ -n "$team" ]] && args+=(--form-string "organizationId=$team")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -w '%{http_code}' -X POST "${args[@]}" \
    --form-string "url=$url" --form-string "analysisType=quick" "$API/submissions/file")"
  BODY="$(cat "$TMP/body")"
}

register() { # register NAME -> prints "Bearer <access token>"
  local name="$1_$SUFFIX"
  local body
  body="$(curl -fsS --max-time 20 -X POST "$API/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$name\",\"email\":\"$name@example.com\",\"password\":\"$PASSWORD\"}")" \
    || fail "register $name failed"
  local t
  t="$(printf '%s' "$body" | jq -r '.data.accessToken // empty')"
  [[ -n "$t" ]] || fail "no token for $name: $body"
  # Visiting the profile syncs the account into the gateway's users table.
  curl -fsS --max-time 20 -H "Authorization: Bearer $t" "$API/users/me" >/dev/null || true
  printf 'Bearer %s' "$t"
}

log "Target gateway: $BASE_URL"
ANA="$(register ana)"; BEN="$(register ben)"; CY="$(register cy)"; DAN="$(register dan)"
ok "registered ana, ben, cy, dan"

# ── 1. Team and invitations ──────────────────────────────────────
log "1. create a team, invite"
req POST /orgs "$ANA" '{"name":"  Blue   Team "}'; expect 201 "ana creates a team"
TEAM="$(jq -r .id <<<"$BODY")"
[[ "$(jq -r .name <<<"$BODY")" == "Blue Team" ]] || fail "name not cleaned: $BODY"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"BEN_$SUFFIX@example.com\",\"role\":\"member\"}"
expect 201 "ana invites ben (address in capitals)"
BEN_CODE="$(jq -r .code <<<"$BODY")"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"cy_$SUFFIX@example.com\",\"role\":\"viewer\"}"
expect 201 "ana invites cy as viewer"
CY_CODE="$(jq -r .code <<<"$BODY")"
CY_INVITE_ID="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"x_$SUFFIX@example.com\",\"role\":\"owner\"}"
expect 400 "can't invite straight to owner"
req POST "/orgs/$TEAM/invitations" "$BEN" "{\"email\":\"x_$SUFFIX@example.com\"}"
expect 404 "ben (not yet a member) can't invite"

# ── 2. Invitations are bound to their address ────────────────────
log "2. invitation rules"
req POST /invitations/accept "$CY" "{\"code\":\"$BEN_CODE\"}"; expect 403 "cy can't use ben's link"
req GET /invitations "$CY"; expect 200 "cy lists invitations"
[[ "$(jq 'length' <<<"$BODY")" == "1" ]] || fail "cy should see 1 invitation: $BODY"
req POST /invitations/accept "$CY" "{\"id\":\"$CY_INVITE_ID\"}"
expect 403 "an unverified address can't accept from the list"
req POST /invitations/accept "$BEN" "{\"code\":\"$BEN_CODE\"}"; expect 200 "ben joins with his link"
req POST /invitations/accept "$BEN" "{\"code\":\"$BEN_CODE\"}"; expect 404 "a link works once"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"ben_$SUFFIX@example.com\"}"
expect 409 "can't invite someone already in"

# ── 3. Team scans ────────────────────────────────────────────────
log "3. team scans"
upload "$BEN" "https://example.com/team-$SUFFIX" "$TEAM"; expect 200 "ben scans into the team"
SCAN="$(jq -r .id <<<"$BODY")"
[[ "$(jq -r .organization_id <<<"$BODY")" == "$TEAM" ]] || fail "scan not saved to team: $BODY"
upload "$BEN" "https://example.com/personal-$SUFFIX"; expect 200 "ben scans for himself"
BEN_PERSONAL="$(jq -r .id <<<"$BODY")"
upload "$DAN" "https://example.com/x-$SUFFIX" "$TEAM"; expect 403 "an outsider can't scan into the team"
req GET "/submissions/$SCAN" "$ANA"; expect 200 "ana (owner) reads ben's team scan"
req GET "/submissions/$SCAN" "$CY"; expect 404 "cy can't read it before joining"
req GET "/submissions/$BEN_PERSONAL" "$ANA"; expect 404 "ana can't read ben's personal scan"
req POST /invitations/accept "$CY" "{\"code\":\"$CY_CODE\"}"; expect 200 "cy joins as viewer"
req GET "/submissions/$SCAN" "$CY"; expect 200 "cy reads the team scan"
req GET "/submissions/$SCAN/analyses" "$CY"; expect 200 "cy reads its results"
upload "$CY" "https://example.com/v-$SUFFIX" "$TEAM"; expect 403 "a viewer can't scan into the team"
req GET "/submissions?organization=$TEAM" "$CY"; expect 200 "cy lists team scans"
[[ "$(jq "[.[] | select(.id == \"$SCAN\")] | length" <<<"$BODY")" == "1" ]] || fail "team list misses the scan: $BODY"
[[ "$(jq "[.[] | select(.id == \"$BEN_PERSONAL\")] | length" <<<"$BODY")" == "0" ]] || fail "team list leaks a personal scan"
req GET "/submissions?organization=$TEAM" "$DAN"; expect 404 "an outsider can't list team scans"
req GET "/orgs/$TEAM" "$DAN"; expect 404 "an outsider can't see the team"
req GET "/orgs/$TEAM" "$CY"; expect 200 "cy sees the team"
[[ "$(jq '.members | length' <<<"$BODY")" == "3" ]] || fail "expected 3 members: $BODY"
[[ "$(jq '.invitations | length' <<<"$BODY")" == "0" ]] || fail "viewers shouldn't see invitations"

# ── 4. Team API keys ─────────────────────────────────────────────
log "4. team keys"
req POST "/orgs/$TEAM/api-keys" "$BEN" '{"name":"ci"}'; expect 403 "a member can't make team keys"
req POST "/orgs/$TEAM/api-keys" "$ANA" '{"name":"ci","scopes":["read","scan"]}'; expect 201 "ana makes a team key"
TKEY="$(jq -r .api_key <<<"$BODY")"
upload "key:$TKEY" "https://example.com/key-$SUFFIX"; expect 200 "the key scans"
KEY_SCAN="$(jq -r .id <<<"$BODY")"
[[ "$(jq -r .organization_id <<<"$BODY")" == "$TEAM" ]] || fail "key scan not in team: $BODY"
req GET "/submissions/$KEY_SCAN" "$CY"; expect 200 "the team sees the key's scan"
req GET /submissions "key:$TKEY"; expect 200 "the key lists scans"
[[ "$(jq "[.[] | select(.id == \"$SCAN\")] | length" <<<"$BODY")" == "1" ]] || fail "key list should be the team's: $BODY"
upload "$ANA" "https://example.com/ana-$SUFFIX"; ANA_PERSONAL="$(jq -r .id <<<"$BODY")"
req GET "/submissions/$ANA_PERSONAL" "key:$TKEY"; expect 404 "the key can't read its maker's personal scans"
req GET /users/me "key:$TKEY"; expect 403 "the key can't read the account"
req GET "/orgs/$TEAM" "key:$TKEY"; expect 403 "the key can't manage the team"
req GET /users/me/api-keys "$ANA"; expect 200 "ana lists personal keys"
[[ "$(jq 'length' <<<"$BODY")" == "0" ]] || fail "team keys shouldn't show as personal: $BODY"
BEN_ID="$(curl -fsS -H "Authorization: $ANA" "$API/orgs/$TEAM" | jq -r '.members[] | select(.role=="member") | .userId')"
req PATCH "/orgs/$TEAM/members/$BEN_ID" "$ANA" '{"role":"admin"}'; expect 200 "ana makes ben an admin"
req POST "/orgs/$TEAM/api-keys" "$BEN" '{"name":"ben-ci"}'; expect 201 "ben (admin) makes a team key"
BKEY="$(jq -r .api_key <<<"$BODY")"
req GET /submissions "key:$BKEY"; expect 200 "ben's key works"
req PATCH "/orgs/$TEAM/members/$BEN_ID" "$ANA" '{"role":"member"}'; expect 200 "ana makes ben a member again"
req GET /submissions "key:$BKEY"; expect 401 "ben's key stopped with his admin rights"
req GET /submissions "key:$TKEY"; expect 200 "ana's key still works"

# ── 5. Role rules ────────────────────────────────────────────────
log "5. role rules"
ANA_ID="$(curl -fsS -H "Authorization: $ANA" "$API/orgs/$TEAM" | jq -r '.members[] | select(.isYou) | .userId')"
CY_ID="$(curl -fsS -H "Authorization: $ANA" "$API/orgs/$TEAM" | jq -r '.members[] | select(.role=="viewer") | .userId')"
req DELETE "/orgs/$TEAM/members/$ANA_ID" "$ANA"; expect 409 "the last owner can't leave"
req PATCH "/orgs/$TEAM/members/$ANA_ID" "$ANA" '{"role":"admin"}'; expect 409 "the last owner can't step down"
req DELETE "/orgs/$TEAM/members/$CY_ID" "$BEN"; expect 403 "a member can't remove people"
req PATCH "/orgs/$TEAM" "$BEN" '{"name":"Red"}'; expect 403 "a member can't rename"
req DELETE "/orgs/$TEAM" "$BEN"; expect 403 "a member can't delete the team"
req DELETE "/orgs/$TEAM/members/$CY_ID" "$ANA"; expect 204 "ana removes cy"
req GET "/submissions/$SCAN" "$CY"; expect 404 "cy lost access at once"

# ── 6. Deleting the team ─────────────────────────────────────────
log "6. delete the team"
req DELETE "/orgs/$TEAM" "$ANA"; expect 204 "ana deletes the team"
req GET "/submissions/$SCAN" "$BEN"; expect 200 "ben still has his scan"
[[ "$(jq -r '.organizationId' <<<"$BODY")" == "null" ]] || fail "scan should be personal again: $BODY"
req GET "/submissions/$SCAN" "$ANA"; expect 404 "ana no longer sees ben's scan"
req GET /submissions "key:$TKEY"; expect 401 "the team's keys are gone"
req GET /orgs "$ANA"; expect 200 "ana lists teams"
[[ "$(jq 'length' <<<"$BODY")" == "0" ]] || fail "ana should have no teams: $BODY"

# ── 7. Account deletion ─────────────────────────────────────────
log "7. an owner deletes their account"
req POST /orgs "$DAN" '{"name":"Green"}'; expect 201 "dan creates a team"
GREEN="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$GREEN/invitations" "$DAN" "{\"email\":\"cy_$SUFFIX@example.com\",\"role\":\"viewer\"}"
CY_CODE2="$(jq -r .code <<<"$BODY")"
req POST "/orgs/$GREEN/invitations" "$DAN" "{\"email\":\"ben_$SUFFIX@example.com\",\"role\":\"admin\"}"
BEN_CODE2="$(jq -r .code <<<"$BODY")"
req POST /invitations/accept "$CY" "{\"code\":\"$CY_CODE2\"}"; expect 200 "cy joins as viewer"
req POST /invitations/accept "$BEN" "{\"code\":\"$BEN_CODE2\"}"; expect 200 "ben joins as admin"
upload "$DAN" "https://example.com/dan-$SUFFIX" "$GREEN"; expect 200 "dan scans into the team"
DAN_SCAN="$(jq -r .id <<<"$BODY")"
req DELETE /users/me "$DAN"; expect 204 "dan deletes his account"
req GET "/orgs/$GREEN" "$BEN"; expect 200 "the team lives on"
[[ "$(jq -r '.role' <<<"$BODY")" == "owner" ]] || fail "ben (the admin) should now own it: $BODY"
[[ "$(jq '.members | length' <<<"$BODY")" == "2" ]] || fail "dan should be gone: $BODY"
req GET "/submissions/$DAN_SCAN" "$CY"; expect 200 "dan's team scan stays with the team"
req DELETE "/orgs/$GREEN" "$BEN"; expect 204 "clean up"

log "All team checks passed."
