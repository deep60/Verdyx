#!/usr/bin/env bash
# TAXII / STIX smoke test, through the API gateway: access rules and response
# shapes. For a deep check with a real TAXII client and strict STIX
# validation, run scripts/test/taxii_check.py as well.
#
#   1. discovery and the API root are public and use the TAXII media type
#   2. collections need an API key (Bearer, X-API-Key or HTTP Basic)
#   3. "My scans" and one collection per team; other people's are 404
#   4. a team key sees its team's collection only
#   5. a scan's STIX bundle is readable only by those who can see the scan
#
# Usage:  BASE_URL=http://localhost:8080 scripts/test/taxii-smoke.sh
# Requires: curl, jq, base64. Exit code 0 on success.
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

get() { # get URL [curl args...] -> STATUS, BODY, headers in $TMP/h
  local url="$1"; shift
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -D "$TMP/h" -w '%{http_code}' "$@" "$url")"
  BODY="$(cat "$TMP/body")"
}
expect() { [[ "$STATUS" == "$1" ]] || fail "$2: expected $1, got $STATUS. Body: $BODY"; ok "$2 ($STATUS)"; }
register() {
  local name="$1_$SUFFIX" body t
  body="$(curl -fsS -X POST "$API/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$name\",\"email\":\"$name@example.com\",\"password\":\"$PASSWORD\"}")" || fail "register $name"
  t="$(jq -r '.data.accessToken // empty' <<<"$body")"
  curl -fsS -H "Authorization: Bearer $t" "$API/users/me" >/dev/null || true
  printf 'Bearer %s' "$t"
}

log "Target gateway: $BASE_URL"
ANA="$(register ana)"; DAN="$(register dan)"
TEAM="$(curl -fsS -X POST -H "Authorization: $ANA" -H 'Content-Type: application/json' -d '{"name":"Feed Team"}' "$API/orgs" | jq -r .id)"
KEY="$(curl -fsS -X POST -H "Authorization: $ANA" -H 'Content-Type: application/json' -d '{"name":"feed","scopes":["read"]}' "$API/auth/api-key" | jq -r .api_key)"
TKEY="$(curl -fsS -X POST -H "Authorization: $ANA" -H 'Content-Type: application/json' -d '{"name":"team feed","scopes":["read"]}' "$API/orgs/$TEAM/api-keys" | jq -r .api_key)"
DKEY="$(curl -fsS -X POST -H "Authorization: $DAN" -H 'Content-Type: application/json' -d '{"name":"feed","scopes":["read"]}' "$API/auth/api-key" | jq -r .api_key)"

log "1. discovery"
get "$BASE_URL/taxii2/"; expect 200 "discovery is public"
grep -qi '^content-type: application/taxii+json;version=2.1' "$TMP/h" || fail "media type: $(grep -i content-type "$TMP/h")"
jq -e '.api_roots | length == 1' <<<"$BODY" >/dev/null || fail "api_roots: $BODY"
get "$BASE_URL/taxii2/api/"; expect 200 "the API root is public"
jq -e '.versions == ["application/taxii+json;version=2.1"]' <<<"$BODY" >/dev/null || fail "versions: $BODY"

log "2. collections need a key"
get "$BASE_URL/taxii2/api/collections/"; expect 401 "no key"
get "$BASE_URL/taxii2/api/collections/" -H "X-API-Key: $KEY"; expect 200 "X-API-Key"
get "$BASE_URL/taxii2/api/collections/" -H "Authorization: Bearer $KEY"; expect 200 "Bearer"
get "$BASE_URL/taxii2/api/collections/" -u "taxii:$KEY"; expect 200 "HTTP Basic, as TAXII clients send it"
get "$BASE_URL/taxii2/api/collections/" -u "taxii:vdx_$(printf '0%.0s' {1..64})"; expect 401 "a wrong key"

log "3. which collections"
get "$BASE_URL/taxii2/api/collections/" -u "taxii:$KEY"
jq -e '[.collections[].title] == ["My scans", "Team: Feed Team"]' <<<"$BODY" >/dev/null || fail "titles: $BODY"
jq -e 'all(.collections[]; .can_read and (.can_write | not))' <<<"$BODY" >/dev/null || fail "read-only"
MINE="$(jq -r '.collections[0].id' <<<"$BODY")"
ok "ana sees My scans and her team"
get "$BASE_URL/taxii2/api/collections/$MINE/objects/" -u "taxii:$KEY"; expect 200 "objects"
jq -e 'has("more") and (.objects | type == "array")' <<<"$BODY" >/dev/null || fail "envelope: $BODY"
get "$BASE_URL/taxii2/api/collections/$MINE/objects/" -u "taxii:$DKEY"; expect 404 "dan can't read ana's collection"
get "$BASE_URL/taxii2/api/collections/$TEAM/objects/" -u "taxii:$DKEY"; expect 404 "dan can't read ana's team"
get "$BASE_URL/taxii2/api/collections/$MINE/objects/?added_after=yesterday" -u "taxii:$KEY"; expect 400 "a bad added_after"
get "$BASE_URL/taxii2/api/collections/$MINE/objects/?next=garbage" -u "taxii:$KEY"; expect 400 "a bad next"

log "4. team keys"
get "$BASE_URL/taxii2/api/collections/" -u "taxii:$TKEY"; expect 200 "a team key lists collections"
jq -e '[.collections[].id] == ["'"$TEAM"'"]' <<<"$BODY" >/dev/null || fail "team key should see only its team: $BODY"
ok "a team key sees only its team"
get "$BASE_URL/taxii2/api/collections/$MINE/objects/" -u "taxii:$TKEY"; expect 404 "a team key can't read its maker's scans"

log "5. a scan's STIX bundle"
printf 'feed smoke %s\n' "$SUFFIX" > "$TMP/f.txt"
SCAN="$(curl -fsS -X POST -H "Authorization: $ANA" -F "file=@$TMP/f.txt" "$API/submissions/file" | jq -r .id)"
get "$API/submissions/$SCAN/stix" -H "Authorization: $ANA"; expect 200 "ana downloads its bundle"
grep -qi '^content-type: application/stix+json;version=2.1' "$TMP/h" || fail "STIX media type"
jq -e '.type == "bundle" and (.id | startswith("bundle--"))' <<<"$BODY" >/dev/null || fail "bundle: $BODY"
get "$API/submissions/$SCAN/stix" -H "Authorization: $DAN"; expect 404 "dan can't"

if [[ -n "${FEED_KEY_FILE:-}" ]]; then
  { echo "ANA='$ANA'"; echo "FEED_KEY=$KEY"; echo "TEAM_FEED_KEY=$TKEY"; echo "TEAM=$TEAM"; echo "SUFFIX=$SUFFIX"; } > "$FEED_KEY_FILE"
fi
log "All TAXII checks passed."
