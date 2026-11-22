#!/bin/sh
# Backups of the Postgres that runs on the VM (docker-compose.gcp.yml).
# Runs inside the `pg-backup` container, next to `postgres`.
#
#   vm-backup.sh            loop: one backup a day at BACKUP_AT_UTC
#   vm-backup.sh now        take one backup now
#   vm-backup.sh list       list the backup days in R2
#   vm-backup.sh restore [DAY]
#                           restore DAY (YYYY-MM-DD, default: the newest) into
#                           the local databases. Refuses any database that
#                           already has tables, so start it before the
#                           services have run their migrations.
#
# A backup is, for each database: pg_dump (custom format) -> check that
# pg_restore can read it -> encrypt with AES-256 -> upload to
# s3://$BACKUP_S3_BUCKET/pg/<day>/<db>.dump.enc. This is the same layout and
# encryption as the old Neon backups, so those restore the same way.
#
# The full restore test, retention and alerting happen off the box, in
# .github/workflows/db-backup.yml (scripts/backup/verify-backup.sh), so this
# 1 GB VM never runs a second Postgres.
#
# Env:
#   POSTGRES_PASSWORD      the verdyx_user password (required)
#   PGHOST                 default: postgres
#   BACKUP_PASSPHRASE      encrypts the dumps (required to back up or restore)
#   BACKUP_S3_BUCKET       R2 bucket (required to back up or restore)
#   BACKUP_S3_ENDPOINT     https://<account>.r2.cloudflarestorage.com
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY   an R2 key for that bucket
#   BACKUP_AT_UTC          HH:MM, default 20:30 (the workflow checks at 21:17)
#   BACKUP_DATABASES       optional space-separated list
set -eu

export PGHOST="${PGHOST:-postgres}" PGUSER="${PGUSER:-verdyx_user}" PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
# R2 rejects some of the newer default checksum headers on older SDK combos.
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
DATABASES="${BACKUP_DATABASES:-verdyx_users verdyx_gateway verdyx_analysis verdyx_submissions verdyx_bounty verdyx_consensus verdyx_reputation verdyx_payments verdyx_notifications}"
AT="${BACKUP_AT_UTC:-20:30}"

log() { echo "[pg-backup] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

configured() {
  [ -n "${BACKUP_PASSPHRASE:-}" ] && [ -n "${BACKUP_S3_BUCKET:-}" ] && [ -n "${BACKUP_S3_ENDPOINT:-}" ]
}

need_config() {
  configured || { log "BACKUP_PASSPHRASE, BACKUP_S3_BUCKET and BACKUP_S3_ENDPOINT must be set"; exit 1; }
}

# The postgres image has no S3 client; install one the first time.
need_aws() {
  command -v aws >/dev/null 2>&1 && return
  log "installing aws-cli"
  apk add --no-cache --quiet aws-cli >/dev/null
}

s3() { aws s3 "$@" --endpoint-url "$BACKUP_S3_ENDPOINT" --only-show-errors; }

wait_for_postgres() {
  i=0
  until pg_isready -q -d verdyx; do
    i=$((i + 1)); [ "$i" -ge 60 ] && { log "postgres is not ready"; return 1; }
    sleep 2
  done
}

backup_once() {
  need_config; need_aws; wait_for_postgres
  day="$(date -u +%Y-%m-%d)"
  work="$(mktemp -d)"
  failed=""
  for db in $DATABASES; do
    f="$work/$db.dump"
    if ! pg_dump --format=custom --no-owner --no-acl --dbname "$db" --file "$f"; then
      log "$db: dump FAILED"; failed="$failed $db"; continue
    fi
    # A truncated or empty archive fails here instead of being uploaded.
    if ! pg_restore --list "$f" >/dev/null; then
      log "$db: dump is unreadable"; failed="$failed $db"; continue
    fi
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE -in "$f" -out "$f.enc"
    if s3 cp "$f.enc" "s3://$BACKUP_S3_BUCKET/pg/$day/$db.dump.enc"; then
      log "$db: uploaded ($(du -h "$f" | cut -f1))"
    else
      log "$db: upload FAILED"; failed="$failed $db"
    fi
    rm -f "$f" "$f.enc"
  done
  rm -rf "$work"
  if [ -n "$failed" ]; then log "FAILED:$failed"; return 1; fi
  log "backup $day complete"
}

days() { aws s3 ls "s3://$BACKUP_S3_BUCKET/pg/" --endpoint-url "$BACKUP_S3_ENDPOINT" | awk '/PRE /{print $2}' | tr -d / | sort; }

restore() {
  need_config; need_aws; wait_for_postgres
  day="${1:-}"
  [ -n "$day" ] || day="$(days | tail -1)"
  [ -n "$day" ] || { log "no backups found in s3://$BACKUP_S3_BUCKET/pg/"; exit 1; }
  log "restoring $day"
  work="$(mktemp -d)"
  failed=""
  for db in $DATABASES; do
    tables="$(psql -d "$db" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
    if [ "$tables" -ne 0 ]; then
      log "$db: already has $tables tables; not touching it"; failed="$failed $db"; continue
    fi
    if ! s3 cp "s3://$BACKUP_S3_BUCKET/pg/$day/$db.dump.enc" "$work/$db.dump.enc"; then
      log "$db: no backup for $day"; failed="$failed $db"; continue
    fi
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$work/$db.dump.enc" -out "$work/$db.dump"
    if pg_restore --no-owner --no-acl --exit-on-error --dbname "$db" "$work/$db.dump"; then
      log "$db: restored $(psql -d "$db" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") tables"
    else
      log "$db: restore FAILED"; failed="$failed $db"
    fi
    rm -f "$work/$db.dump" "$work/$db.dump.enc"
  done
  rm -rf "$work"
  if [ -n "$failed" ]; then log "FAILED:$failed"; exit 1; fi
  log "restore of $day complete"
}

seconds_until() {
  now="$(date -u +%s)"
  next="$(date -u -d "$(date -u +%Y-%m-%d) $AT:00" +%s 2>/dev/null || date -u -d "$AT" +%s)"
  [ "$next" -le "$now" ] && next=$((next + 86400))
  echo $((next - now))
}

loop() {
  if ! configured; then
    log "backups are not configured (BACKUP_PASSPHRASE, BACKUP_S3_BUCKET, BACKUP_S3_ENDPOINT); idle"
    while :; do sleep 3600; done
  fi
  need_aws
  while :; do
    wait="$(seconds_until)"
    log "next backup at $AT UTC, in ${wait}s"
    sleep "$wait"
    backup_once || log "backup failed; the nightly verify workflow will report it"
  done
}

case "${1:-loop}" in
  loop) loop ;;
  now) backup_once ;;
  list) need_config; need_aws; days ;;
  restore) restore "${2:-}" ;;
  *) echo "usage: $0 [loop|now|list|restore [YYYY-MM-DD]]" >&2; exit 2 ;;
esac
