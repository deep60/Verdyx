#!/usr/bin/env bash
# Runs inside the "Verdyx scan" composite action (action.yml).
set -euo pipefail

CLI="$GITHUB_ACTION_PATH/../sdk/typescript/bin/verdyx.js"

if ! command -v node >/dev/null 2>&1; then
  echo "::error title=Verdyx::Node.js 18 or later is needed; add actions/setup-node before this step"
  exit 1
fi
major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$major" -lt 18 ]; then
  echo "::error title=Verdyx::Node.js 18 or later is needed, found $(node --version)"
  exit 1
fi

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

targets=()
while IFS= read -r line; do
  case "$line" in
    file$'\t'*) targets+=("${line#file$'\t'}") ;;
    *) echo "$line" ;;
  esac
done < <(node "$GITHUB_ACTION_PATH/expand.mjs")

while IFS= read -r line || [ -n "$line" ]; do
  url="$(trim "$line")"
  [ -n "$url" ] && targets+=("$url")
done <<< "$INPUT_URLS"

if [ "${#targets[@]}" -eq 0 ]; then
  echo "::error title=Verdyx::nothing to scan; set paths or urls"
  exit 1
fi

if [ -z "${VERDYX_API_KEY:-}" ]; then
  echo "::notice title=Verdyx::no api-key set, so these scans are anonymous and more tightly rate limited"
fi
echo "Scanning ${#targets[@]} target(s)"

results="${RUNNER_TEMP:-/tmp}/verdyx-results.json"
rm -f "$results"  # never report a previous step's results
args=(scan --fail-on "$INPUT_FAIL_ON" --timeout "$INPUT_TIMEOUT" --output "$results" --verbose)
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && args+=(--summary "$GITHUB_STEP_SUMMARY")
[ -n "$INPUT_TEAM" ] && args+=(--team "$INPUT_TEAM")

set +e
node "$CLI" "${args[@]}" -- "${targets[@]}"
code=$?
set -e

# Annotations and outputs from the JSON results.
if [ -f "$results" ]; then
  node - "$results" <<'EOF'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const rank = { clean: 0, unknown: 0, suspicious: 1, malicious: 2 };
const esc = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
const escMsg = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
let worst = "clean";
let flagged = 0;
const limit = data.failOn === "never" ? Infinity : rank[data.failOn];
for (const r of data.results) {
  if ((rank[r.verdict] ?? 0) > (rank[worst] ?? 0)) worst = r.verdict;
  if (r.status === "failed") {
    console.log(`::warning title=${esc("Verdyx: scan failed")}::${escMsg(`${r.target ?? r.id}: ${r.failureReason ?? "unknown reason"} ${r.reportUrl}`)}`);
    continue;
  }
  if ((rank[r.verdict] ?? 0) >= 1) {
    const level = (rank[r.verdict] ?? 0) >= limit ? "error" : "warning";
    if (level === "error") flagged++;
    console.log(`::${level} title=${esc(`Verdyx: ${r.verdict}`)}::${escMsg(`${r.target ?? r.id} is ${r.verdict} (${r.votes.malicious + r.votes.suspicious}/${r.votes.total} engines). ${r.reportUrl}`)}`);
  }
}
if (data.results.length === 0) worst = "unknown";
// Annotations go to stdout (the runner reads workflow commands there); outputs go to $GITHUB_OUTPUT.
fs.appendFileSync(process.env.GITHUB_OUTPUT, `verdict=${worst}\nflagged=${flagged}\nresults=${process.argv[2]}\n`);
EOF
fi

exit "$code"
