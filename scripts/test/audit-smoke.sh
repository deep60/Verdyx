#!/usr/bin/env bash
# Audit log smoke test, through the API gateway. Creates throwaway accounts
# (ana, ben, dan), does things, and checks the right events land in the right
# logs:
#
#   1. a failed sign-in to an existing account shows in that account's log
#   2. key, profile and team actions show in the actor's log with IP and browser
#   3. role changes show in the log of the person they were made to
#   4. a team's log has every member's and team key's actions, without IPs,
#      and only owners and admins can read it
#   5. paging, action filters and CSV export
#   6. after someone deletes their account, logs no longer show their name
#
# Usage:  BASE_URL=http://localhost:8080 scripts/test/audit-smoke.sh
# Requires: curl, jq. Exit code 0 on success.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="$BASE_URL/api/v1"
PASSWORD="${SMOKE_PASSWORD:-SmokeTest123!}"
SUFFIX="$(date +%s)$$"
UA="audit-smoke/1.0"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "  ✗ $*"; exit 1; }
ok()   { log "  ✓ $*"; }

req() { # req METHOD PATH AUTH [JSON] -> STATUS, BODY
  local method="$1" path="$2" auth="$3" data="${4:-}" args=(-A "$UA")
  case "$auth" in
    -) ;;
    key:*) args+=(-H "X-API-Key: ${auth#key:}") ;;
    *) args+=(-H "Authorization: $auth") ;;
  esac
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data "$data")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" "${args[@]}" "$API$path")"
  BODY="$(cat "$TMP/body")"
}
expect() {
  [[ "$STATUS" == "$1" ]] || fail "$2: expected $1, got $STATUS. Body: $BODY"
  ok "$2 ($STATUS)"
}
upload() { # upload AUTH URL [TEAM]
  local auth="$1" args=(-A "$UA")
  case "$auth" in key:*) args+=(-H "X-API-Key: ${auth#key:}") ;; *) args+=(-H "Authorization: $auth") ;; esac
  [[ -n "${3:-}" ]] && args+=(--form-string "organizationId=$3")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -w '%{http_code}' -X POST "${args[@]}" \
    --form-string "url=$2" "$API/submissions/file")"
  BODY="$(cat "$TMP/body")"
}
register() {
  local name="$1_$SUFFIX" body t
  body="$(curl -fsS -A "$UA" --max-time 20 -X POST "$API/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$name\",\"email\":\"$name@example.com\",\"password\":\"$PASSWORD\"}")" || fail "register $name"
  t="$(jq -r '.data.accessToken // empty' <<<"$body")"
  [[ -n "$t" ]] || fail "no token for $name"
  curl -fsS -A "$UA" -H "Authorization: Bearer $t" "$API/users/me" >/dev/null || true
  printf 'Bearer %s' "$t"
}
has() { # has ACTION in BODY's events
  jq -e --arg a "$1" '[.events[] | select(.action == $a)] | length > 0' <<<"$BODY" >/dev/null
}
must_have() { for a in "$@"; do has "$a" || fail "missing $a in: $(jq -c '[.events[].action]' <<<"$BODY")"; done; ok "has ${*}"; }

log "Target gateway: $BASE_URL"
ANA="$(register ana)"; BEN="$(register ben)"; DAN="$(register dan)"
ok "registered ana, ben, dan"

log "1. a failed sign-in"
req POST /auth/login - "{\"identifier\":\"ana_$SUFFIX@example.com\",\"password\":\"wrong-$SUFFIX\"}"
[[ "$STATUS" == "401" ]] || fail "wrong password should be 401, got $STATUS"
req POST /auth/login - "{\"identifier\":\"nobody_$SUFFIX@example.com\",\"password\":\"x\"}"
req POST /auth/login - "{\"identifier\":\"ana_$SUFFIX@example.com\",\"password\":\"$PASSWORD\"}"; expect 200 "ana signs in"

log "2. ana's own actions"
req POST /auth/api-key "$ANA" '{"name":"laptop"}'; expect 200 "ana makes a key"
KEY_ID="$(jq -r .key_id <<<"$BODY")"
req DELETE "/users/me/api-keys/$KEY_ID" "$ANA"; expect 204 "ana revokes it"
req PUT /users/me "$ANA" '{"bio":"threat hunter"}'; expect 200 "ana updates her profile"
req POST /orgs "$ANA" '{"name":"Audit Team"}'; expect 201 "ana creates a team"
TEAM="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"ben_$SUFFIX@example.com\",\"role\":\"member\"}"; expect 201 "ana invites ben"
CODE="$(jq -r .code <<<"$BODY")"
req POST /invitations/accept "$BEN" "{\"code\":\"$CODE\"}"; expect 200 "ben joins"
upload "$BEN" "https://example.com/audit-$SUFFIX" "$TEAM"; expect 200 "ben scans into the team"
SCAN="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$TEAM/api-keys" "$ANA" '{"name":"pipeline"}'; expect 201 "ana makes a team key"
TKEY="$(jq -r .api_key <<<"$BODY")"
upload "key:$TKEY" "https://example.com/key-$SUFFIX"; expect 200 "the team key scans"
BEN_ID="$(curl -fsS -H "Authorization: $ANA" "$API/orgs/$TEAM" | jq -r '.members[] | select(.role=="member") | .userId')"
req PATCH "/orgs/$TEAM/members/$BEN_ID" "$ANA" '{"role":"viewer"}'; expect 200 "ana makes ben a viewer"

req GET /users/me/audit "$ANA"; expect 200 "ana reads her activity"
must_have auth.register auth.login auth.login_failed api_key.created api_key.revoked account.updated \
  team.created team.invitation.sent team.api_key.created team.member.role_changed
jq -e '[.events[] | select(.action=="auth.login_failed")][0] | .actor == null and .ip != null' <<<"$BODY" >/dev/null \
  || fail "failed sign-in should have no actor and an IP"
jq -e --arg ua "$UA" '[.events[] | select(.action=="api_key.created")][0] | .ip != null and .userAgent == $ua and .details.name == "laptop"' <<<"$BODY" >/dev/null \
  || fail "key event lacks IP, browser or name: $(jq -c '.events[] | select(.action=="api_key.created")' <<<"$BODY")"
ok "events carry IP, browser and details"
[[ "$(jq '[.events[] | select(.action=="auth.login_failed")] | length' <<<"$BODY")" == "1" ]] \
  || fail "the unknown address's failed sign-in must not appear"
ok "a failed sign-in to an unknown address isn't recorded against anyone"
jq -e '[.events[] | select(.details.prefix != null)] | all(.details.prefix | startswith("vdx_"))' <<<"$BODY" >/dev/null || fail "prefix"
grep -q '"api_key":' <<<"$BODY" && fail "a key leaked into the log" || ok "no key material in the log"

log "3. ben's log"
req GET /users/me/audit "$BEN"; expect 200 "ben reads his activity"
must_have team.invitation.accepted scan.created team.member.role_changed
jq -e '[.events[] | select(.action=="team.member.role_changed")][0] | .details.to == "viewer" and .actor.username != null' <<<"$BODY" >/dev/null \
  || fail "ben should see who changed his role"
ok "ben sees the role change made to him"

log "4. the team's log"
req GET "/orgs/$TEAM/audit" "$ANA"; expect 200 "ana reads the team log"
must_have team.created team.invitation.sent team.invitation.accepted scan.created team.api_key.created team.member.role_changed
jq -e '[.events[] | select(.action=="scan.created" and .via=="api_key")] | length == 1' <<<"$BODY" >/dev/null \
  || fail "the team key's scan should be marked as an API key"
ok "the team key's scan is in the team log"
jq -e '[.events[] | has("ip") or has("userAgent")] | any | not' <<<"$BODY" >/dev/null || fail "team log must not show IPs"
ok "no IPs or browsers in the team log"
req GET "/orgs/$TEAM/audit" "$BEN"; expect 403 "a viewer can't read the team log"
req GET "/orgs/$TEAM/audit" "$DAN"; expect 404 "an outsider can't either"
req GET "/orgs/$TEAM/audit" "key:$TKEY"; expect 403 "nor can a team key"

log "5. paging, filters, export"
req GET "/users/me/audit?limit=2" "$ANA"; expect 200 "first page"
[[ "$(jq '.events | length' <<<"$BODY")" == "2" ]] || fail "limit"
NEXT="$(jq -r .nextBefore <<<"$BODY")"
[[ "$NEXT" != "null" ]] || fail "expected another page"
FIRST_IDS="$(jq -c '[.events[].id]' <<<"$BODY")"
req GET "/users/me/audit?limit=2&before=$NEXT" "$ANA"; expect 200 "second page"
jq -e --argjson first "$FIRST_IDS" '[.events[].id] | all(. < ($first | min))' <<<"$BODY" >/dev/null || fail "pages overlap"
ok "pages don't overlap"
req GET "/users/me/audit?action=team.member" "$ANA"; expect 200 "filter by action"
jq -e '[.events[].action] | length > 0 and all(startswith("team.member"))' <<<"$BODY" >/dev/null || fail "filter"
req GET "/users/me/audit?action=team%25" "$ANA"; expect 400 "a filter can't carry wildcards"
req GET "/users/me/audit?format=csv" "$ANA"; expect 200 "CSV export"
grep -qi '^content-type: text/csv' "$TMP/headers" || fail "CSV content type"
head -1 <<<"$BODY" | grep -q '^time,action,actor,via,subject,target_type,target_id,ip,user_agent,details' || fail "CSV header: $(head -1 <<<"$BODY")"
req GET "/orgs/$TEAM/audit?format=csv" "$ANA"
head -1 <<<"$BODY" | grep -q '^time,action,actor,via,subject,target_type,target_id,details$' || fail "team CSV header"
ok "CSV exports have the right columns"

log "6. a member deletes their account"
req DELETE /users/me "$BEN"; expect 204 "ben deletes his account"
req GET "/orgs/$TEAM/audit?action=scan." "$ANA"; expect 200 "ana reads the team log"
grep -q "ben_$SUFFIX" <<<"$BODY" && fail "ben's name is still in the log" || true
jq -e '[.events[] | select(.via=="session") | .actor.username] | all(test("^deleted_[0-9a-f]{32}$"))' <<<"$BODY" >/dev/null \
  || fail "ben's scan should show a deleted account: $(jq -c '[.events[].actor]' <<<"$BODY")"
ok "the log shows a deleted account, not ben"
req DELETE "/orgs/$TEAM" "$ANA"; expect 204 "clean up"
log "All audit checks passed."
