# Postgres on the VM

Production's Postgres runs in the `postgres` container of
`docker-compose.gcp.yml`, next to the services, instead of on Neon.

**Why.** Neon's free plan has a monthly compute allowance, and its compute
only sleeps when nothing is connected. Nine services each hold a small
connection pool, and the gateway's bounty indexer polls every 30 seconds, so
the database never slept. In November 2026 the allowance ran out. Neon then
refused every connection ("Your account or project has exceeded the quota"),
every service crash-looped, the API returned 502, and the nightly backups
failed too.

**How it's set up.**

- `postgres:18-alpine`, tuned for a 1 GB VM:
  - `shared_buffers=32MB` and `max_connections=50`
  - JIT and parallel workers off
  - capped at 256 MB of memory
- No published port. Only containers on the compose network can reach it,
  so it needs no TLS.
- Data lives in the `verdyx_pg_data` Docker volume.
- `database/init/01-init-databases.sql` creates the nine per-service databases
  and their extensions the first time the volume is empty. The services create
  their own tables through their migrations.
- Watchtower doesn't touch it. A major-version upgrade means editing the image
  tag and doing a dump and restore.

## Backups

The `pg-backup` container (`scripts/backup/vm-backup.sh`) runs every night at
20:30 UTC. For each database it:
1. dumps it with `pg_dump`
2. checks that the dump is readable
3. encrypts it with AES-256
4. uploads it to `s3://$BACKUP_S3_BUCKET/pg/<day>/<db>.dump.enc` on R2

The layout and encryption are the same as the old Neon backups.

At 21:17 UTC the **Database backup** workflow
(`scripts/backup/verify-backup.sh`) checks the newest set off the box:
- **Fresh:** the set must be under 26 hours old.
- **Restorable:** every database must restore into a scratch Postgres with
  tables.
- **Retention:** sets older than 30 days are deleted, but the newest 7 are
  always kept.

If any of that fails, GitHub emails you. Postgres isn't exposed to the
internet, so the workflow never connects to it. It only reads R2.

Useful commands on the VM (from `/opt/verdyx`):

```bash
sudo docker compose -f docker-compose.gcp.yml run --rm pg-backup now      # back up now
sudo docker compose -f docker-compose.gcp.yml run --rm pg-backup list     # list backup days
sudo docker compose -f docker-compose.gcp.yml logs --tail 20 pg-backup    # last nightly run
sudo docker compose -f docker-compose.gcp.yml exec postgres psql -U verdyx_user -d verdyx_gateway
```

## Moving from Neon (one time)

The data comes from the last good Neon backup in R2. **2026-11-19** was the
last one before the quota ran out. Rows written after it, before Neon started
refusing connections, exist only in Neon. If they matter, dump them once Neon
lets you connect again (its quota resets each billing month, or upgrade for a
day).

Everything below runs on the VM, in `/opt/verdyx`.

**1. Get this version of the repository.**

```bash
cd /opt/verdyx
sudo git fetch origin main && sudo git checkout FETCH_HEAD -- docker-compose.gcp.yml database/init scripts/backup
```

**2. Add the new settings** to the env file in `/opt/verdyx`
(`sudo nano /opt/verdyx/.env`):

| Setting | Value |
|---|---|
| `POSTGRES_PASSWORD` | a new random value: `openssl rand -hex 32`. Hex only, because it goes inside a URL. |
| `BACKUP_PASSPHRASE` | the **same** passphrase as the GitHub secret of that name, or the old backups can't be decrypted |
| `BACKUP_S3_BUCKET` | same as the GitHub variable (`verdyx-backups`) |
| `BACKUP_S3_ENDPOINT` | same as the GitHub variable |
| `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY` | the R2 key for the backup bucket (the GitHub secrets of those names) |

`PG_BASE_URL` is no longer read; delete it.

**3. Stop the crash-looping services and start Postgres on its own.**

```bash
C="sudo docker compose -f docker-compose.gcp.yml"
$C stop api-gateway user-service analysis-engine bounty-manager submission-service \
  consensus-service payment-service reputation-service notification-service
$C up -d postgres
$C ps postgres            # wait for "healthy"
```

**4. Restore the last Neon backup** before any service starts. The services
would otherwise create empty tables, and the restore refuses to touch a
database that already has tables.

```bash
$C run --rm pg-backup list
$C run --rm pg-backup restore 2026-11-19
```

It should end with `restore of 2026-11-19 complete` and print a table count
for each of the nine databases.

**5. Start everything.**

```bash
$C up -d
$C ps
curl -s https://api.verdyx.dev/health
```

The services run any migrations newer than the backup when they start.

**6. Take a first backup on the VM, then verify it.**

```bash
$C run --rm pg-backup now
```

Then in GitHub go to **Actions → Database backup → Run workflow**. It should
end with `backup <today> verified`. You can delete the `BACKUP_PG_BASE_URL`
GitHub secret; nothing reads it now.

### If a service started before the restore

The restore stops with "already has N tables". Since there is no real data
on the VM yet, start over with an empty volume:

```bash
$C stop
$C rm -f postgres
sudo docker volume rm verdyx_pg_data
```

Then repeat from step 3.

## Restoring later

To roll back to a backup, first stop the services. Then rename the broken
databases out of the way, or start over with an empty volume as above.
Finally run `restore <day>` and start the services again. The restore only
fills databases that have no tables, so it can't overwrite data by mistake.
