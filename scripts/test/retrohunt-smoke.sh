#!/usr/bin/env bash
# Retrohunt smoke test: a gateway plus an analysis engine built with YARA
# (`--features yara-engine`). Creates throwaway accounts and harmless files
# that contain a marker string, then checks:
#
#   1. bad rules are refused before they're queued (include, risky modules)
#   2. a hunt over your uploads finds your marked file and nothing else
#   3. a team hunt finds the team's files only; outsiders can't hunt a team
#   4. one hunt at a time; compile errors are reported; hunts can be
#      cancelled and removed; nobody else can read your hunt
#
# Usage:  BASE_URL=http://localhost:8080 scripts/test/retrohunt-smoke.sh
# Requires: curl, jq. Exit code 0 on success.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
API="$BASE_URL/api/v1"
PASSWORD="${SMOKE_PASSWORD:-SmokeTest123!}"
SUFFIX="$(date +%s)$$"
MARK="VERDYX-RETROHUNT-$SUFFIX"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "  ✗ $*"; exit 1; }
ok()   { log "  ✓ $*"; }

req() {
  local method="$1" path="$2" auth="$3" data="${4:-}" args=()
  [[ "$auth" != "-" ]] && args+=(-H "Authorization: $auth")
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' --data "$data")
  STATUS="$(curl -sS --max-time 20 -o "$TMP/body" -w '%{http_code}' -X "$method" ${args[@]+"${args[@]}"} "$API$path")"
  BODY="$(cat "$TMP/body")"
}
expect() { [[ "$STATUS" == "$1" ]] || fail "$2: expected $1, got $STATUS. Body: $BODY"; ok "$2 ($STATUS)"; }
upload() { # upload AUTH NAME CONTENT [TEAM] -> id
  printf '%s\n' "$3" > "$TMP/$2"
  local args=(-H "Authorization: $1" -F "file=@$TMP/$2")
  [[ -n "${4:-}" ]] && args+=(--form-string "organizationId=$4")
  curl -fsS --max-time 20 -X POST "${args[@]}" "$API/submissions/file" | jq -r .id
}
register() {
  local name="$1_$SUFFIX" body t
  body="$(curl -fsS --max-time 20 -X POST "$API/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$name\",\"email\":\"$name@example.com\",\"password\":\"$PASSWORD\"}")" || fail "register $name"
  t="$(jq -r '.data.accessToken // empty' <<<"$body")"
  curl -fsS -H "Authorization: Bearer $t" "$API/users/me" >/dev/null || true
  printf 'Bearer %s' "$t"
}
hunt() { # hunt AUTH RULE [TEAM]
  local team="null"; [[ -n "${3:-}" ]] && team="\"$3\""
  req POST /retrohunts "$1" "$(jq -n --arg r "$2" --argjson t "$team" '{rule: $r, teamId: $t}')"
}
wait_done() { # wait_done AUTH ID -> BODY of the finished job
  for _ in $(seq 1 60); do
    req GET "/retrohunts/$2" "$1"
    case "$(jq -r .status <<<"$BODY")" in completed|failed|cancelled) return 0 ;; esac
    sleep 1
  done
  fail "hunt $2 didn't finish: $BODY"
}
RULE="rule Marker_$SUFFIX { strings: \$a = \"$MARK\" condition: \$a }"

log "Target gateway: $BASE_URL"
ANA="$(register ana)"; BEN="$(register ben)"; DAN="$(register dan)"
req POST /orgs "$ANA" '{"name":"Hunt Team"}'; TEAM="$(jq -r .id <<<"$BODY")"
req POST "/orgs/$TEAM/invitations" "$ANA" "{\"email\":\"ben_$SUFFIX@example.com\",\"role\":\"member\"}"
req POST /invitations/accept "$BEN" "{\"code\":\"$(jq -r .code <<<"$BODY")\"}"; expect 200 "ben joins ana's team"
A="$(upload "$ANA" a.txt "hello $MARK world")"
B="$(upload "$ANA" b.txt "nothing here")"
C="$(upload "$BEN" c.txt "team file $MARK" "$TEAM")"
D="$(upload "$DAN" d.txt "dan's file $MARK")"
ok "uploaded marked files for ana, the team and dan"

log "1. rules are checked first"
hunt "$ANA" 'include "/etc/passwd" rule a { condition: true }'; expect 400 "include is refused"
hunt "$ANA" 'import "console" rule a { condition: true }'; expect 400 "the console module is refused"
hunt "$ANA" '   '; expect 400 "an empty rule is refused"

log "2. ana hunts her uploads"
hunt "$ANA" "$RULE"; expect 201 "ana starts a hunt"; H1="$(jq -r .id <<<"$BODY")"
hunt "$ANA" "$RULE"
[[ "$STATUS" == "409" || "$STATUS" == "201" ]] || fail "second hunt: $STATUS"
[[ "$STATUS" == "409" ]] && ok "one hunt at a time (409)" || { log "  (the first hunt had already finished)"; wait_done "$ANA" "$(jq -r .id <<<"$BODY")"; }
wait_done "$ANA" "$H1"
jq -e --arg a "$A" '.status == "completed" and .matches == 1 and ([.results[].submissionId] == [$a]) and .filesTotal >= 2' <<<"$BODY" >/dev/null \
  || fail "ana's hunt: $BODY"
jq -e --arg n "Marker_$SUFFIX" '.results[0].rules == [$n] and .ruleNames == [$n]' <<<"$BODY" >/dev/null || fail "rule names: $BODY"
ok "found only ana's marked file, with the rule name"

log "3. team hunts"
hunt "$ANA" "$RULE" "$TEAM"; expect 201 "ana hunts the team's files"
wait_done "$ANA" "$(jq -r .id <<<"$BODY")"
jq -e --arg c "$C" '.status == "completed" and ([.results[].submissionId] == [$c])' <<<"$BODY" >/dev/null || fail "team hunt: $BODY"
ok "found the team's file only (not ana's own, not dan's)"
hunt "$DAN" "$RULE" "$TEAM"; expect 404 "an outsider can't hunt the team"
hunt "$BEN" "$RULE"; expect 201 "ben hunts his own uploads"; HB="$(jq -r .id <<<"$BODY")"
wait_done "$BEN" "$HB"
jq -e --arg c "$C" '[.results[].submissionId] == [$c]' <<<"$BODY" >/dev/null || fail "ben's own hunt: $BODY"
ok "ben's own uploads include the file he saved to the team"
req GET "/retrohunts/$HB" "$ANA"; expect 404 "ana can't read ben's hunt"

log "4. errors, cancelling, removing"
hunt "$ANA" 'rule Broken { condition: $nope }'; expect 201 "a rule that won't compile is queued"
wait_done "$ANA" "$(jq -r .id <<<"$BODY")"
jq -e '.status == "failed" and (.message | startswith("the rule doesn'"'"'t compile"))' <<<"$BODY" >/dev/null || fail "compile error: $BODY"
ok "the compile error is reported"
hunt "$ANA" "$RULE"; HC="$(jq -r .id <<<"$BODY")"
req DELETE "/retrohunts/$HC" "$ANA"; expect 204 "cancel a hunt"
wait_done "$ANA" "$HC"
[[ "$(jq -r .status <<<"$BODY")" =~ ^(cancelled|completed)$ ]] || fail "cancel: $BODY"
ok "the hunt stopped ($(jq -r .status <<<"$BODY"))"
req DELETE "/retrohunts/$HC" "$ANA"; expect 204 "remove a finished hunt"
req GET "/retrohunts/$HC" "$ANA"; expect 404 "it's gone"
req GET /retrohunts "$ANA"; expect 200 "list hunts"
[[ "$(jq 'length' <<<"$BODY")" -ge 3 ]] || fail "list: $BODY"
grep -q "$MARK" <<<"$(jq -c '[.[] | del(.ruleNames)]' <<<"$BODY")" && fail "the list shouldn't carry rule text" || true
log "All retrohunt checks passed. (unused: B=$B D=$D)"
