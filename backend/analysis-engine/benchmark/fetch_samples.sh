#!/usr/bin/env bash
# Download the benchmark samples listed in manifest.json into $BENCH/samples.
#
# Meant to run inside a throwaway debian container on the server (see
# run_on_server.sh), never on a workstation: the malicious half is live malware.
# The files are only read by the analysis engines, never executed.
#
#   samples/malicious/<sha256>   one file per manifest entry, hash-verified
#   samples/clean/<source>/...   every file from each official release archive
#
# Already-downloaded files are skipped, so a re-run only fetches what's missing.
set -euo pipefail

BENCH="${BENCH:-/bench}"
MANIFEST="$BENCH/manifest.json"
MAL="$BENCH/samples/malicious"
CLEAN="$BENCH/samples/clean"

: "${ABUSE_CH_API_KEY:?ABUSE_CH_API_KEY is not set}"

apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends ca-certificates curl jq 7zip unzip >/dev/null

mkdir -p "$MAL" "$CLEAN"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok=0; skipped=0; failed=0
for sha in $(jq -r '.malicious[].sha256' "$MANIFEST"); do
  if [[ -s "$MAL/$sha" ]]; then skipped=$((skipped + 1)); continue; fi

  curl -fsS --retry 3 --max-time 120 -o "$tmp/s.zip" \
    -H "Auth-Key: $ABUSE_CH_API_KEY" \
    --data-urlencode "query=get_file" --data-urlencode "sha256_hash=$sha" \
    https://mb-api.abuse.ch/api/v1/ || { failed=$((failed + 1)); continue; }

  # A missing sample comes back as a JSON error instead of a zip.
  if ! 7z x -y -pinfected -o"$tmp/x" "$tmp/s.zip" >/dev/null 2>&1; then
    echo "not available: $sha"; failed=$((failed + 1)); rm -rf "$tmp/x"; continue
  fi
  f="$(find "$tmp/x" -type f | head -n 1)"
  if [[ -n "$f" ]] && echo "$sha  $f" | sha256sum -c --status -; then
    mv "$f" "$MAL/$sha"; chmod 0444 "$MAL/$sha"; ok=$((ok + 1))
  else
    echo "hash mismatch: $sha"; failed=$((failed + 1))
  fi
  rm -rf "$tmp/x" "$tmp/s.zip"
  sleep 1
done
echo "malicious: $ok downloaded, $skipped already present, $failed failed"

for row in $(jq -r '.clean_sources[] | "\(.name)|\(.url)"' "$MANIFEST"); do
  name="${row%%|*}"; url="${row#*|}"
  if [[ -d "$CLEAN/$name" ]]; then echo "clean: $name already present"; continue; fi
  curl -fsSL --retry 3 -o "$tmp/c.zip" "$url"
  mkdir -p "$tmp/c" && unzip -q -o "$tmp/c.zip" -d "$tmp/c"
  mv "$tmp/c" "$CLEAN/$name"
  rm -f "$tmp/c.zip"
  echo "clean: $name ($(find "$CLEAN/$name" -type f | wc -l) files)"
done
