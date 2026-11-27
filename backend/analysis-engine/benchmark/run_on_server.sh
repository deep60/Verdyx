#!/usr/bin/env bash
# Run the detection benchmark on the production server and copy the report back.
#
#   backend/analysis-engine/benchmark/run_on_server.sh ubuntu@<server> [ssh options...]
#
# BENCHMARK_CLAMAV=off skips ClamAV, and BENCHMARK_PE_MODEL=off skips the
# Windows program model (EMBER2024); each is used only when production has it
# set up and it answers. BENCHMARK_MEMORY (default 700m) caps the run's memory. To stop a run on the server: ssh in and `docker rm -f verdyx-benchmark`.
#
# Example:
#   backend/analysis-engine/benchmark/run_on_server.sh ubuntu@68.233.97.210 -i ~/.ssh/verdyx-oracle
#
# Samples are downloaded and analysed on the server, inside containers. Nothing
# but the manifest goes up and nothing but the report comes back.
set -euo pipefail

target="${1:?usage: run_on_server.sh user@host [ssh options...]}"
shift
here="$(cd "$(dirname "$0")" && pwd)"
remote=/opt/verdyx-benchmark
image="${BENCHMARK_IMAGE:-ghcr.io/deep60/verdyx-analysis-engine:latest}"

ssh "$@" "$target" "sudo mkdir -p $remote/out && sudo chown -R \$USER $remote && chmod 700 $remote"
scp "${@}" "$here/manifest.json" "$here/fetch_samples.sh" "$target:$remote/"

ssh "$@" "$target" bash -s -- "$remote" "$image" "${BENCHMARK_CLAMAV:-on}" "${BENCHMARK_MEMORY:-700m}" "${BENCHMARK_PE_MODEL:-on}" <<'REMOTE'
set -euo pipefail
remote="$1"; image="$2"; BENCHMARK_CLAMAV="$3"; memory="$4"; BENCHMARK_PE_MODEL="$5"
export ABUSE_CH_API_KEY="$(sudo grep -E '^ABUSE_CH_API_KEY=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'")"

echo "== Fetching samples"
docker run --rm -e ABUSE_CH_API_KEY -e BENCH=/bench -v "$remote:/bench" \
  debian:trixie-slim bash /bench/fetch_samples.sh

# ClamAV runs on its own VM. When production has it switched on, give the
# benchmark a network so it can reach clamd too; otherwise keep it offline.
# Hash-reputation feeds stay off either way (verdyx-benchmark clears their keys).
clam_enabled="$(sudo grep -E '^ENABLE_CLAMAV=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
clam_host="$(sudo grep -E '^CLAMAV_HOST=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
# Before relying on it, check clamd answers from a container: an unreachable
# clamd costs the full timeout on every file and stalls the run for hours.
# BENCHMARK_CLAMAV=off skips it outright.
clam_ok=false
if [ "${BENCHMARK_CLAMAV:-on}" != "off" ] && [ "$clam_enabled" = "true" ] && [ -n "$clam_host" ]; then
  echo "== ClamAV: checking $clam_host"
  if docker run --rm --network bridge -e "ADDR=$clam_host" debian:trixie-slim timeout 10 bash -c '
      h="${ADDR%:*}"; p="${ADDR##*:}"
      exec 3<>"/dev/tcp/$h/$p" || exit 1
      printf "zPING\0" >&3
      IFS= read -r -d "" -t 5 reply <&3; [ "$reply" = "PONG" ]' 2>/dev/null; then
    clam_ok=true
  else
    echo "== ClamAV: no answer from $clam_host; running without it" >&2
    echo "   (check production scans too: the engine reaches it the same way)" >&2
  fi
fi
# The Windows program model (EMBER2024) runs on the same VM as clamd, behind
# PE_MODEL_URL with ML_SERVICE_TOKEN. Used only if its /health says a model is
# loaded; the token goes to the container by name, never on a command line.
pe_url="$(sudo grep -E '^PE_MODEL_URL=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
export ML_SERVICE_TOKEN="$(sudo grep -E '^ML_SERVICE_TOKEN=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
pe_ok=false
if [ "${BENCHMARK_PE_MODEL:-on}" != "off" ] && [ -n "$pe_url" ]; then
  echo "== Windows program model: checking $pe_url"
  if docker run --rm --network bridge curlimages/curl:8.11.1 -sf --max-time 10 "$pe_url/health" 2>/dev/null \
      | grep -Eq '"loaded"[[:space:]]*:[[:space:]]*true'; then
    pe_ok=true
  else
    echo "== Windows program model: not answering, or no model loaded; running without it" >&2
  fi
fi

# A network only when an engine on the other VM is in use. Hash-reputation
# feeds stay off either way (verdyx-benchmark clears their keys).
if [ "$clam_ok" = "true" ] || [ "$pe_ok" = "true" ]; then
  net=(--network bridge)
else
  net=(--network none)
fi
if [ "$clam_ok" = "true" ]; then
  echo "== ClamAV: $clam_host"
  net+=(-e ENABLE_CLAMAV=true -e "CLAMAV_HOST=$clam_host" -e CLAMAV_TIMEOUT_SECONDS=30)
else
  echo "== ClamAV: off"
  net+=(-e ENABLE_CLAMAV=false)
fi
if [ "$pe_ok" = "true" ]; then
  echo "== Windows program model: $pe_url"
  net+=(-e "PE_MODEL_URL=$pe_url" -e ML_SERVICE_TOKEN)
else
  echo "== Windows program model: off"
  net+=(-e PE_MODEL_URL=)
fi

echo "== Running the benchmark"
docker pull -q "$image" >/dev/null
# What was measured, for the published page: when, which build, which engines.
revision="$(docker image inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image" 2>/dev/null || true)"
digest="$(docker image inspect -f '{{ index .RepoDigests 0 }}' "$image" 2>/dev/null || true)"
printf '{"ranAt":"%s","image":"%s","revision":"%s","clamav":%s,"peModel":%s}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$digest" "$revision" "$clam_ok" "$pe_ok" > "$remote/out/run.json"
rm -f "$remote/out/report.md" "$remote/out/report.json"
# A run outlives the ssh session (Ctrl+C here doesn't stop it there), so clear
# any earlier one before starting, and run it detached under a fixed name.
docker rm -f verdyx-benchmark >/dev/null 2>&1 || true
# Older runs had no name: find them by their command (never the live engine).
stale="$(docker ps --no-trunc --format '{{.ID}} {{.Command}}' | grep '"verdyx-benchmark ' | cut -d' ' -f1 || true)"
if [ -n "$stale" ]; then
  echo "== Stopping $(echo "$stale" | wc -l) earlier benchmark run(s)"
  echo "$stale" | xargs docker rm -f >/dev/null
fi
docker run -d --name verdyx-benchmark --memory "$memory" "${net[@]}" \
  -v "$remote/manifest.json:/bench/manifest.json:ro" \
  -v "$remote/samples:/bench/samples:ro" \
  -v "$remote/out:/out" \
  --user "$(id -u)" \
  "$image" verdyx-benchmark \
    --manifest /bench/manifest.json \
    --samples /bench/samples \
    --clean-dir /usr/bin \
    --out /out >/dev/null
docker logs -f verdyx-benchmark &
logs=$!
# Every two minutes, show what the run is using, so a stall is visible.
while [ "$(docker inspect -f '{{.State.Running}}' verdyx-benchmark 2>/dev/null)" = "true" ]; do
  sleep 120
  docker stats --no-stream --format '   [{{.Name}}] CPU {{.CPUPerc}}, memory {{.MemUsage}}' verdyx-benchmark 2>/dev/null || true
done
code="$(docker inspect -f '{{.State.ExitCode}} {{.State.OOMKilled}}' verdyx-benchmark)"
kill "$logs" 2>/dev/null || true
docker rm verdyx-benchmark >/dev/null
case "$code" in
  "0 false") ;;
  *" true") echo "== The benchmark ran out of memory ($memory). Try BENCHMARK_MEMORY=1500m." >&2; exit 1 ;;
  *) echo "== The benchmark failed (exit ${code%% *})." >&2; exit 1 ;;
esac
REMOTE

mkdir -p "$here/results"
scp "${@}" "$target:$remote/out/report.md" "$target:$remote/out/report.json" "$target:$remote/out/run.json" "$here/results/"
echo "Report: $here/results/report.md"
echo "To update the public page: python3 $here/publish.py"
