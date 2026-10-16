#!/usr/bin/env bash
# Point the current shell at one Verdyx service database.
#
#   source scripts/development/use-service-db.sh gateway
#   source scripts/development/use-service-db.sh users
#
# Reads the root .env. Does not print the URL.
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "Source this script: source scripts/development/use-service-db.sh <service>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
set -a
# shellcheck disable=SC1091
source "$ROOT_DIR/.env"
set +a

service="${1:-}"
case "$service" in
  gateway)        export DATABASE_URL="${GATEWAY_DATABASE_URL:?}" ;;
  users|user)     export DATABASE_URL="${USER_DATABASE_URL:?}" ;;
  analysis)       export DATABASE_URL="${ANALYSIS_DATABASE_URL:?}" ;;
  bounty)         export DATABASE_URL="${BOUNTY_DATABASE_URL:?}" ;;
  submissions)    export DATABASE_URL="${SUBMISSION_DATABASE_URL:?}" ;;
  consensus)      export DATABASE_URL="${CONSENSUS_DATABASE_URL:?}" ;;
  payments|payment) export DATABASE_URL="${PAYMENT_DATABASE_URL:?}" ;;
  reputation)     export DATABASE_URL="${REPUTATION_DATABASE_URL:?}" ;;
  notifications|notification) export DATABASE_URL="${NOTIFICATION_DATABASE_URL:?}" ;;
  *)
    echo "Unknown service: $service" >&2
    echo "Use: gateway, users, analysis, bounty, submissions, consensus, payments, reputation, notifications" >&2
    return 1
    ;;
esac

echo "DATABASE_URL set for ${service} ($(printf '%s' "$DATABASE_URL" | sed -E 's#.*@##; s#\?.*##'))"
