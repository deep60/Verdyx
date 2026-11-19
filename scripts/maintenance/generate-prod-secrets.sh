#!/usr/bin/env bash
# Generate strong production secrets and emit them as a .env.production
# diff. Use this once during go-live. The script prints values to stdout
# only — it never writes them to disk so they don't accidentally land in
# git history.
#
# Usage:
#   scripts/maintenance/generate-prod-secrets.sh > prod-secrets.env
#   chmod 600 prod-secrets.env
#
# Then load into your secrets manager (AWS Secrets Manager, Vault, etc.)
# and delete the local copy.
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "[error] openssl is required" >&2; exit 1
fi

gen()   { openssl rand -hex "$1"; }
genb64() { openssl rand -base64 "$1" | tr -d '\n='; }

cat <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Treat every value as a secret.
POSTGRES_PASSWORD=$(gen 32)
REDIS_PASSWORD=$(gen 32)
JWT_SECRET=$(gen 32)
MINIO_ROOT_PASSWORD=$(gen 32)
WEBHOOK_SIGNING_SECRET=$(gen 32)
PGADMIN_PASSWORD=$(genb64 24)

# Optional — generate if you don't have one yet.
SESSION_SECRET=$(gen 32)
COOKIE_SECRET=$(gen 32)

# No on-chain signing key is needed: services hold none, and people sign
# marketplace transactions in their own wallets.
EOF
