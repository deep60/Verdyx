#!/usr/bin/env bash
# Nightly check of the database backups, run by .github/workflows/db-backup.yml.
#
# The backups themselves are made on the VM by scripts/backup/vm-backup.sh
# (the pg-backup container), because Postgres there is not reachable from the
# internet. This script proves they are usable, off the box:
#
#   1. The newest backup day in R2 must be no older than MAX_AGE_HOURS, so a
#      VM that silently stopped backing up fails this job.
#   2. Every database of that day is downloaded, decrypted and restored into a
#      throwaway Postgres, and must contain tables. (An untested backup is not
#      a backup.)
#   3. Backup days older than the retention period are deleted, but the
#      newest seven are always kept.
#
# Env (all required unless noted):
#   BACKUP_PASSPHRASE    decrypts the dumps
#   BACKUP_S3_BUCKET     R2 bucket for backups
#   BACKUP_S3_ENDPOINT   https://<account>.r2.cloudflarestorage.com
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   an R2 API key for that bucket
#   RESTORE_URL          postgres://... of an empty scratch server
#   BACKUP_DATABASES     (optional) space-separated list
#   BACKUP_RETENTION_DAYS (optional, default 30)
#   MAX_AGE_HOURS        (optional, default 26)
#
# Restoring for real is done on the VM:
#   docker compose -f docker-compose.gcp.yml run --rm pg-backup restore [YYYY-MM-DD]
# See docs/operations/postgres-on-vm.md.
set -euo pipefail

: "${BACKUP_PASSPHRASE:?}" "${BACKUP_S3_BUCKET:?}" "${BACKUP_S3_ENDPOINT:?}" "${RESTORE_URL:?}"
DATABASES="${BACKUP_DATABASES:-verdyx_users verdyx_gateway verdyx_analysis verdyx_submissions verdyx_bounty verdyx_consensus verdyx_reputation verdyx_payments verdyx_notifications}"
RETENTION="${BACKUP_RETENTION_DAYS:-30}"
MAX_AGE="${MAX_AGE_HOURS:-26}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

s3() { aws s3 "$@" --endpoint-url "$BACKUP_S3_ENDPOINT" --only-show-errors; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
days() { aws s3 ls "s3://$BACKUP_S3_BUCKET/pg/" --endpoint-url "$BACKUP_S3_ENDPOINT" | awk '/PRE /{print $2}' | tr -d / | sort; }

failed=()
day="$(days | tail -1)"
if [[ -z "$day" ]]; then
  log "no backups in s3://$BACKUP_S3_BUCKET/pg/"; exit 1
fi
# Newest object time of that day, not just its date, so a backup that started
# but uploaded nothing recent still counts as stale.
newest="$(aws s3 ls "s3://$BACKUP_S3_BUCKET/pg/$day/" --endpoint-url "$BACKUP_S3_ENDPOINT" | awk '{print $1" "$2}' | sort | tail -1)"
age_h=$(( ($(date -u +%s) - $(date -u -d "$newest" +%s)) / 3600 ))
log "newest backup: $day (uploaded $newest, ${age_h}h ago)"
if (( age_h > MAX_AGE )); then
  log "STALE: the newest backup is older than ${MAX_AGE}h; check the pg-backup container on the VM"
  failed+=("stale")
fi

for db in $DATABASES; do
  enc="$WORK/$db.dump.enc"
  dump="$WORK/$db.dump"
  if ! s3 cp "s3://$BACKUP_S3_BUCKET/pg/$day/$db.dump.enc" "$enc"; then
    log "$db: missing from $day"; failed+=("$db"); continue
  fi
  if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$enc" -out "$dump"; then
    log "$db: decryption FAILED"; failed+=("$db"); continue
  fi

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
  rm -f "$enc" "$dump"
done

log "retention: removing backups older than $RETENTION days, always keeping the newest 7"
cutoff="$(date -u -d "-$RETENTION days" +%Y-%m-%d)"
# If the VM stops uploading, this must not age every backup out of existence.
days | head -n -7 | while read -r d; do
  if [[ "$d" < "$cutoff" ]]; then log "  deleting $d"; s3 rm --recursive "s3://$BACKUP_S3_BUCKET/pg/$d/"; fi
done

if (( ${#failed[@]} )); then
  log "FAILED: ${failed[*]}"
  exit 1
fi
log "backup $day verified"
