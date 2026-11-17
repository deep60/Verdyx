#!/usr/bin/env bash
# Data-retention smoke test, through the API gateway. Creates throwaway
# accounts and checks:
#
#   1. who may delete a scan (its maker, a team owner or admin; never a scan
#      with a bounty), and that deleting is recorded
#   2. personal and team retention settings: allowed values, who may set them
#   3. the data export: what's in it, what never is, who may download it
#   4. API keys: deleting needs the write scope, exporting is refused
#
# The retention job itself runs daily; scripts that can reach the database
# (see docs/operations/retention.md) backdate scans to check it. This script
# writes the ids they need to $RETENTION_IDS_FILE when set.
#
# Usage:  BASE_URL=http://localhost:8080 scripts/test/retention-smoke.sh
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

req() {
  local method="$1" path="$2" auth="$3" data="${4:-}" args=()
  case "$auth" in
    -) ;;
    key:*) args+=(-H "X-API-Key: ${auth#key:}") ;;
    *) args+=(-H "Authorization: $auth") ;;
  esac
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data "$data")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" ${args[@]+"${args[@]}"} "$API$path")"
  BODY="$(cat "$TMP/body")"
}
expect() { [[ "$STATUS" == "$1" ]] || fail "$2: expected $1, got $STATUS. Body: $BODY"; ok "$2 ($STATUS)"; }
scan_url() { # scan_url AUTH URL [TEAM] -> id
  local args=()
  [[ "$1" != "-" ]] && args+=(-H "Authorization: $1")
  [[ -n "${3:-}" ]] && args+=(--form-string "organizationId=$3")
  curl -fsS --max-time 20 -X POST ${args[@]+"${args[@]}"} --form-string "url=$2" "$API/submissions/file" | jq -r .id
}
scan_file() { # scan_file AUTH NAME -> id
  printf 'retention smoke %s %s\n' "$2" "$SUFFIX" > "$TMP/$2"
  curl -fsS --max-time 20 -X POST -H "Authorization: $1" -F "file=@$TMP/$2" "$API/submissions/file" | jq -r .id
}
register() {
  local name="$1_$SUFFIX" body
  body="$(curl -fsS --max-time 20 -X POST "$API/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$name\",\"email\":\"$name@example.com\",\"password\":\"$PASSWORD\"}")" || fail "register $name"
  local t; t="$(jq -r '.data.accessToken // empty' <<<"$body")"
  [[ -n "$t" ]] || fail "no token for $name"
  curl -fsS -H "Authorization: Bearer $t" "$API/users/me" >/dev/null || true
  printf 'Bearer %s' "$t"
}

log "Target gateway: $BASE_URL"
ANA="$(register ana)"; BEN="$(register ben)"
req POST /orgs "$ANA" '{"name":"Retention Team"}'; TEAM="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"ben_$SUFFIX@example.com\",\"role\":\"member\"}"
req POST /invitations/accept "$BEN" "{\"code\":\"$(jq -r .code <<<"$BODY")\"}"; expect 200 "ben joins ana's team"

log "1. deleting a scan"
P1="$(scan_url "$ANA" "https://example.com/p1-$SUFFIX")"
T1="$(scan_url "$ANA" "https://example.com/t1-$SUFFIX" "$TEAM")"
B1="$(scan_url "$BEN" "https://example.com/b1-$SUFFIX" "$TEAM")"
req DELETE "/submissions/$P1" "$BEN"; expect 404 "ben can't delete ana's scan"
req DELETE "/submissions/$T1" "$BEN"; expect 404 "a member can't delete someone else's team scan"
req DELETE "/submissions/$B1" "$ANA"; expect 204 "the owner deletes ben's team scan"
req DELETE "/submissions/$P1" -; expect 401 "signed out can't delete"
req DELETE "/submissions/$P1" "$ANA"; expect 204 "ana deletes her scan"
req GET "/submissions/$P1" "$ANA"; expect 404 "it's gone"
req DELETE "/submissions/$P1" "$ANA"; expect 404 "deleting twice"
req GET "/users/me/audit?action=scan.deleted" "$ANA"
[[ "$(jq '.events | length' <<<"$BODY")" == "2" ]] || fail "expected 2 scan.deleted events: $BODY"
ok "deletions are in ana's activity"

log "2. retention settings"
req GET /users/me/retention "$ANA"; expect 200 "read my retention"
[[ "$(jq -r .scanRetentionDays <<<"$BODY")" == "null" ]] || fail "default should keep scans"
jq -e '.sampleRetentionDays != null and (.choices | index(365))' <<<"$BODY" >/dev/null || fail "policy fields: $BODY"
req PUT /users/me/retention "$ANA" '{"scanRetentionDays":45}'; expect 400 "only offered choices"
req PUT /users/me/retention "$ANA" '{"scanRetentionDays":90}'; expect 200 "ana keeps her scans 90 days"
req GET /users/me/retention "$ANA"
[[ "$(jq -r .scanRetentionDays <<<"$BODY")" == "90" ]] || fail "not saved: $BODY"
req PUT "/orgs/$TEAM/retention" "$BEN" '{"scanRetentionDays":30}'; expect 403 "a member can't set team retention"
req PUT "/orgs/$TEAM/retention" "$ANA" '{"scanRetentionDays":30}'; expect 200 "ana sets team retention to 30 days"
req GET "/orgs/$TEAM" "$BEN"
[[ "$(jq -r .scanRetentionDays <<<"$BODY")" == "30" ]] || fail "team retention not shown: $BODY"
ok "members see the team's retention"

log "3. data export"
F1="$(scan_file "$ANA" sample1.txt)"
req POST /webhooks "$ANA" '{"url":"https://example.com/hook","events":["submission.completed"]}' || true
req POST /auth/api-key "$ANA" '{"name":"export-check","scopes":["read","scan"]}'; RKEY="$(jq -r .api_key <<<"$BODY")"
req GET /users/me/export "$ANA"; expect 200 "ana downloads her data"
grep -qi '^content-disposition: attachment; filename="verdyx-export-' "$TMP/headers" || fail "not a download"
jq -e --arg e "ana_$SUFFIX@example.com" --arg f "$F1" --arg t "$T1" '
  .format == "verdyx-export/1" and .account.email == $e
  and ([.scans[].id] | index($f) and index($t))
  and (.teams | length == 1) and (.apiKeys | length >= 1) and (.activity | length > 0)
  and .retention.scanRetentionDays == 90' <<<"$BODY" >/dev/null || fail "export contents: $(jq -c 'del(.activity)' <<<"$BODY" | cut -c1-600)"
ok "the export has the account, scans, teams, keys and activity"
grep -q "$RKEY" <<<"$BODY" && fail "an API key leaked into the export" || true
jq -e '[.. | objects | keys[]] | (index("key_hash") or index("secret") or index("token_hash")) | not' <<<"$BODY" >/dev/null \
  || fail "the export holds a hash or signing secret field"
ok "no keys, hashes or signing secrets in the export"

log "4. API keys"
req GET /users/me/export "key:$RKEY"; expect 403 "a key can't export the account"
T2="$(scan_url "$ANA" "https://example.com/t2-$SUFFIX")"
req DELETE "/submissions/$T2" "key:$RKEY"; expect 403 "deleting needs the write scope"
req POST /auth/api-key "$ANA" '{"name":"writer","scopes":["write"]}'; WKEY="$(jq -r .api_key <<<"$BODY")"
req DELETE "/submissions/$T2" "key:$WKEY"; expect 204 "a write key deletes"

if [[ -n "${RETENTION_IDS_FILE:-}" ]]; then
  { echo "ANA='$ANA'"; echo "BEN='$BEN'"; echo "TEAM=$TEAM"; echo "T1=$T1"; echo "F1=$F1"; echo "SUFFIX=$SUFFIX"; } > "$RETENTION_IDS_FILE"
fi
log "All retention API checks passed."
