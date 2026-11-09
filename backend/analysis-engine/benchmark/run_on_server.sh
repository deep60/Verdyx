#!/usr/bin/env bash
# Run the detection benchmark on the production server and copy the report back.
#
#   backend/analysis-engine/benchmark/run_on_server.sh ubuntu@<server> [ssh options...]
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

ssh "$@" "$target" bash -s -- "$remote" "$image" <<'REMOTE'
set -euo pipefail
remote="$1"; image="$2"
export ABUSE_CH_API_KEY="$(sudo grep -E '^ABUSE_CH_API_KEY=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'")"

echo "== Fetching samples"
docker run --rm -e ABUSE_CH_API_KEY -e BENCH=/bench -v "$remote:/bench" \
  debian:trixie-slim bash /bench/fetch_samples.sh

# ClamAV runs on its own VM. When production has it switched on, give the
# benchmark a network so it can reach clamd too; otherwise keep it offline.
# Hash-reputation feeds stay off either way (verdyx-benchmark clears their keys).
clam_enabled="$(sudo grep -E '^ENABLE_CLAMAV=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
clam_host="$(sudo grep -E '^CLAMAV_HOST=' /opt/verdyx/.env | cut -d= -f2- | tr -d "\"'" || true)"
if [ "$clam_enabled" = "true" ] && [ -n "$clam_host" ]; then
  echo "== ClamAV: $clam_host"
  net=(--network bridge -e ENABLE_CLAMAV=true -e "CLAMAV_HOST=$clam_host" -e CLAMAV_TIMEOUT_SECONDS=60)
else
  echo "== ClamAV: off"
  net=(--network none -e ENABLE_CLAMAV=false)
fi

echo "== Running the benchmark"
docker pull -q "$image" >/dev/null
docker run --rm --memory 700m "${net[@]}" \
  -v "$remote/manifest.json:/bench/manifest.json:ro" \
  -v "$remote/samples:/bench/samples:ro" \
  -v "$remote/out:/out" \
  --user "$(id -u)" \
  "$image" verdyx-benchmark \
    --manifest /bench/manifest.json \
    --samples /bench/samples \
    --clean-dir /usr/bin \
    --out /out
REMOTE

mkdir -p "$here/results"
scp "${@}" "$target:$remote/out/report.md" "$target:$remote/out/report.json" "$here/results/"
echo "Report: $here/results/report.md"
