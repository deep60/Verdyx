# Retention, backup, and restore

## Retention

Approved rule: keep data indefinitely. Do not auto-delete submissions, artifacts, analysis results, votes, bounties, audit rows, or logs because they are old.

Delete only when someone explicitly removes an account or a submission.

| Action | Database | Object storage |
| --- | --- | --- |
| Account delete (`DELETE /api/v1/users/me`) | user-service anonymizes the user and writes `account.deleted`. Gateway deletes that user’s `submissions` rows. `analysis_results` rows go with them via `ON DELETE CASCADE`. | Each `file_path` is pushed to Redis `artifact_deletions`. The analysis worker deletes the object, or records the key on `artifact_deletions:dead` if storage refuses. |
| Submission delete | Delete the owned `submissions` row only. Do not delete another user’s row. | Same artifact queue. |
| Time-based purge | None. | None. |

Backup files produced by the scripts below are the exception: dump files on disk are kept for 7 days (`BACKUP_RETENTION_DAYS`) so the disk does not fill. That retention applies to backup copies, not to live data.

Logs are not purged by application code. If a log shipper is added later, it must not delete live tables.

## Backups

Two scripts exist. Use both only if you mean to. They do not share a lock.

| Script | What it dumps | Schedule |
| --- | --- | --- |
| `scripts/maintenance/backup.sh` | One `pg_dump` per service database, Redis RDB, optional MinIO mirror, `manifest.json` | Manual, or before a migration. |
| `scripts/backup/pg-backup.sh` | `pg_dumpall`, gzip, optional S3/MinIO upload | Loop, default every 86400 seconds. Verifies gzip before keeping the file. |

Databases covered, matching `database/init/01-init-databases.sql`:

`verdyx`, `verdyx_gateway`, `verdyx_users`, `verdyx_analysis`, `verdyx_bounty`, `verdyx_submissions`, `verdyx_consensus`, `verdyx_payments`, `verdyx_reputation`, `verdyx_notifications`.

A backup that only dumps `verdyx` is not a full backup.

## Restore

Preferred recovery is restore-from-backup, then start the service so `sqlx::migrate!` applies only migrations newer than the dump. Do not edit an applied migration file. Do not delete `_sqlx_migrations` rows unless the migration failed mid-flight and you have confirmed the schema matches the failure note in `docs/database/migrations.md`.

```bash
# Stop writers for the database you are restoring.
docker compose stop api-gateway analysis-engine

# Restore one timestamped backup produced by scripts/maintenance/backup.sh.
./scripts/maintenance/restore.sh --backup backups/<TIMESTAMP> --yes

# Start services. Each one migrates only its own database.
docker compose up -d api-gateway analysis-engine
```

Forward-fix when the bad migration only added objects and live writes must be kept: add a new migration, do not rewrite the old file. See `docs/database/rollback-strategy.md`.

## Restore practice

A restore was not run in this change. Connecting to Postgres was deferred until you approve a specific database. Recovery time is therefore not recorded. When you approve a disposable database, the practice steps are:

1. Note the start time.
2. Run `scripts/maintenance/backup.sh` against that database.
3. Drop one service database.
4. Run `restore.sh` for that backup.
5. Start the service and confirm `/health/ready` and `_sqlx_migrations.success = true`.
6. Record elapsed time in this file.

## Migration procedure

Supported path, and the only one:

1. Empty Postgres volume runs `database/init/01-init-databases.sql` once. That creates databases and extensions. It does not create tables.
2. Each service, on startup, runs `sqlx::migrate!("./migrations")` against its own `DATABASE_URL`. A failed migration returns an error and the process exits. Deployments must treat a non-zero service exit as a failed deploy and must not mark the instance healthy.
3. Do not apply `database/postgres/migrations/*.sql` or `database/schema.sql`. Those are the old single-database design. See `database/postgres/migrations/README.LEGACY.md`.

Clean environment: new volume, init script, then start services. Existing environment: start the new service binary; sqlx applies only pending versions. Never change a file whose version is already in `_sqlx_migrations`.

This session did not execute that procedure against a database.
