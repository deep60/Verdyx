# Migrations & Rollback Strategy

## Source of truth

Each backend service owns its own migrations under
`backend/<service>/migrations/`. On startup the service runs `sqlx::migrate!`,
which applies any pending migrations against its dedicated database
(`verdyx_<service>` — see `database/init/01-init-databases.sql`).

There is no monolithic schema. Files under `database/postgres/migrations/`
and `database/schema.sql` are **legacy reference only** (see
`database/postgres/migrations/README.LEGACY.md`). Do not add new files there
and do not point a service `DATABASE_URL` at a database that was built only
from those files.

Table purpose, sensitive columns, and who may read them are in
`docs/database/data-model.md`. Backup, restore, and the indefinite retention
rule are in `docs/database/retention-and-backup.md`.

## Why we don't ship reversible "down" migrations

`sqlx-cli` supports paired `up.sql`/`down.sql` files, but reversible
migrations in production are an anti-pattern when:

- A migration drops a column or table — running `down` after data has been
  written loses that data.
- Two services depend on overlapping rows — running `down` on one creates
  cross-service inconsistency.
- Auto-generated downs (e.g. for `ALTER TABLE`) silently miss data
  side-effects.

We use a **forward-only migration policy** with a documented rollback
procedure based on backups. This matches what most production Postgres
deployments actually do (Stripe, GitLab, Discourse, etc.).

## Authoring rules

1. **Forward-only.** A new migration adds; it never relies on `down.sql`.
2. **Reversible by design where possible.** Prefer additive changes:
   - Adding a nullable column is safe.
   - Renames are done as `ADD column → backfill → switch reads → switch
     writes → drop old column` across at least two deploys.
   - Type narrowing is done as a new column with a backfill, never a
     destructive `ALTER TYPE`.
3. **Idempotent.** Use `IF NOT EXISTS` / `IF EXISTS` so a partial migration
   can be re-applied safely.
4. **Wrapped in a transaction** unless the operation forbids it (e.g.
   `CREATE INDEX CONCURRENTLY`). sqlx wraps each migration in a transaction
   by default; do not split DDL across files.
5. **No data backfills inline if they take more than a few seconds.** Run
   them as a separate operational step after the schema migration deploys.
6. **One migration = one logical change.** If a feature needs five table
   changes, that's five migration files in one PR, not one giant file.
7. **Filename format.** sqlx requires `<version>_<description>.sql`. Use
   `YYYYMMDDHHMMSS_<snake_case_description>.sql` so chronological order is
   unambiguous across forks.

## Rollback procedure

If a deploy goes bad, treat it as a forward problem first. Roll back the
**code** (re-deploy the previous service version) before touching the
database whenever possible — the previous code can usually still read the
new schema if migrations were additive.

If a destructive schema change ships and must be undone:

### Option A — restore from backup (preferred for prod)

```bash
# 1. Stop the affected service so nothing writes to the bad schema.
docker compose stop <service>

# 2. Restore the per-service database from the most recent good backup.
#    backup.sh produces backups/<TS>/postgres/<dbname>.sql
scripts/maintenance/restore.sh --backup backups/<TS>

# 3. Re-deploy the previous service version (which expects the old schema).
# 4. Start the service back up.
docker compose start <service>
```

### Option B — write a forward "undo" migration

When a backup restore is too costly (e.g. several services share a database,
or you cannot lose the writes that happened between deploy and rollback),
write a new forward migration that reverses the previous change. This goes
through the normal review/test/deploy cycle and is the safest in-place fix.

```sql
-- 20240501120000_revert_users_email_unique.sql
-- Reverts 20240430090000_users_email_unique.sql.
-- The unique constraint conflicted with the legacy SSO sync; revert until
-- backfill ticket VRDX-1234 is shipped.

DROP INDEX IF EXISTS users_email_unique;
```

### Option C — emergency `_sqlx_migrations` surgery (last resort)

If a migration started, partially applied, and left the row in
`_sqlx_migrations` with `success = false`, sqlx will refuse to start the
service. Recovery:

```sql
-- Connect to the affected per-service database.
DELETE FROM _sqlx_migrations WHERE version = <bad_version>;
```

…then take any compensating action manually (drop half-created tables,
etc.), commit a corrected migration with a new version number, and redeploy.
**Never edit a migration file that has been applied to production.**

## Pre-migration backup helper

Before applying a schema change in a non-trivial environment, run
`scripts/maintenance/backup.sh` so Option A is available. CI/CD should run
this as a step before `cargo run` / image start in production.

```bash
scripts/maintenance/backup.sh --backup-root /var/backups/verdyx
```

That snapshot is what `restore.sh --backup <dir>` rolls back to.

## Per-environment policy

| Env       | Migration applies on… | Backup before deploy |
|-----------|----------------------|----------------------|
| Local     | service start        | optional             |
| CI        | service start        | not applicable       |
| Staging   | service start        | yes                  |
| Production | manual gate, then service start | mandatory |

In staging/prod, run migrations during a low-traffic window, and verify the
new service version against a smoke test before cutting traffic over.
