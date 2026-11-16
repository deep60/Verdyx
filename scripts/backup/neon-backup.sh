#!/usr/bin/env bash
# Nightly backup of every Verdyx database on Neon, run by
# .github/workflows/db-backup.yml.
#
# For each database: pg_dump (custom format) → restore it into a throwaway
# Postgres and count its tables (an untested backup is not a backup) →
# encrypt with AES-256 → upload to R2 → delete copies older than the
# retention period.
#
# Env (all required unless noted):
#   PG_BASE_URL          postgres://user:pass@host   (Neon's *direct* host,
#                        not the -pooler one; no database name, no query)
#   BACKUP_PASSPHRASE    encrypts the dumps; keep a copy somewhere safe
#   BACKUP_S3_BUCKET     R2 bucket for backups
#   BACKUP_S3_ENDPOINT   https://<account>.r2.cloudflarestorage.com
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   an R2 API key for that bucket
#   RESTORE_URL          postgres://... of an empty scratch server for the
#                        restore check
#   BACKUP_DATABASES     (optional) space-separated list
#   BACKUP_RETENTION_DAYS (optional, default 30)
#
# Restore one database:
#   aws s3 cp s3://$BUCKET/pg/<date>/<db>.dump.enc . --endpoint-url $ENDPOINT
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE \
#     -in <db>.dump.enc -out <db>.dump
#   pg_restore --no-owner --no-acl -d "<target url>" <db>.dump
set -euo pipefail

: "${PG_BASE_URL:?}" "${BACKUP_PASSPHRASE:?}" "${BACKUP_S3_BUCKET:?}" "${BACKUP_S3_ENDPOINT:?}" "${RESTORE_URL:?}"
DATABASES="${BACKUP_DATABASES:-verdyx_users verdyx_gateway verdyx_analysis verdyx_submissions verdyx_bounty verdyx_consensus verdyx_reputation verdyx_payments verdyx_notifications}"
RETENTION="${BACKUP_RETENTION_DAYS:-30}"
DAY="$(date -u +%Y-%m-%d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

s3() { aws s3 "$@" --endpoint-url "$BACKUP_S3_ENDPOINT" --only-show-errors; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

failed=()
for db in $DATABASES; do
  log "$db: dump"
  dump="$WORK/$db.dump"
  if ! pg_dump --format=custom --no-owner --no-acl --dbname "$PG_BASE_URL/$db?sslmode=require" --file "$dump"; then
    log "$db: dump FAILED"; failed+=("$db"); continue
  fi

  log "$db: restore check"
  scratch="restore_${db}"
  psql "$RESTORE_URL" -qc "DROP DATABASE IF EXISTS $scratch" -c "CREATE DATABASE $scratch" >/dev/null
  if ! pg_restore --no-owner --no-acl --exit-on-error --dbname "${RESTORE_URL%/*}/$scratch" "$dump"; then
    log "$db: restore FAILED"; failed+=("$db"); continue
  fi
  tables="$(psql "${RESTORE_URL%/*}/$scratch" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
  if [[ "${tables:-0}" -eq 0 ]]; then
    log "$db: restored database has no tables"; failed+=("$db"); continue
  fi
  log "$db: restored $tables tables, $(du -h "$dump" | cut -f1)"

  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE \
    -in "$dump" -out "$dump.enc"
  s3 cp "$dump.enc" "s3://$BACKUP_S3_BUCKET/pg/$DAY/$db.dump.enc"
  rm -f "$dump" "$dump.enc"
  log "$db: uploaded"
done

log "retention: removing backups older than $RETENTION days"
cutoff="$(date -u -d "-$RETENTION days" +%Y-%m-%d)"
aws s3 ls "s3://$BACKUP_S3_BUCKET/pg/" --endpoint-url "$BACKUP_S3_ENDPOINT" \
  | awk '/PRE /{print $2}' | tr -d / | while read -r d; do
      if [[ "$d" < "$cutoff" ]]; then log "  deleting $d"; s3 rm --recursive "s3://$BACKUP_S3_BUCKET/pg/$d/"; fi
    done

if (( ${#failed[@]} )); then
  log "FAILED: ${failed[*]}"
  exit 1
fi
log "all databases backed up and verified"
