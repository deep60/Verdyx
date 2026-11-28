#!/usr/bin/env bash
# Print a text profile of each malicious script in the benchmark set, to see
# how the ones the engines miss are hidden. See describe_scripts.py.
#
#   backend/analysis-engine/benchmark/describe_on_server.sh ubuntu@<server> [ssh options...]
#
# DESCRIBE_ONLY="sha-prefix sha-prefix" limits it to some samples.
#
# Runs on the server after run_on_server.sh has fetched the samples, in a
# container with no network and the samples mounted read-only. Only the text
# profile comes back.
set -euo pipefail

target="${1:?usage: describe_on_server.sh user@host [ssh options...]}"
shift
here="$(cd "$(dirname "$0")" && pwd)"
remote=/opt/verdyx-benchmark

scp "${@}" "$here/describe_scripts.py" "$here/manifest.json" "$target:$remote/" >/dev/null
# shellcheck disable=SC2086
ssh "$@" "$target" "docker run --rm --network none --read-only \
  -v $remote/describe_scripts.py:/d.py:ro -v $remote/manifest.json:/m.json:ro \
  -v $remote/samples/malicious:/s:ro python:3.13-slim \
  python3 -I /d.py /m.json /s ${DESCRIBE_ONLY:-}"
