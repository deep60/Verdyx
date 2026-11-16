# Monitoring, error reporting and backups

Three things tell you Verdyx is in trouble before a user does. Each is off until its settings exist, and nothing breaks while it's off.

## 1. Error reporting (Sentry)

**What is reported**
- Every backend service sends `error!` logs and panics, tagged with the service name.
- The website sends uncaught errors and errors caught by its error boundary.
- No performance traces, IP addresses, cookies, request bodies or form input are sent.
- Page addresses are sent without their query string, because reset links carry their code there.

**Set up**
1. Create a free account at sentry.io. Create two projects: **Rust** (`verdyx-backend`) and **React** (`verdyx-website`).
2. **Backend:** add the Rust project's DSN to the server's `/opt/verdyx/.env`:
   ```
   SENTRY_DSN=https://…@….ingest.sentry.io/…
   SENTRY_ENVIRONMENT=production
   ```
   Then restart:
   ```bash
   cd /opt/verdyx && sudo docker compose -f docker-compose.gcp.yml up -d
   ```
   Every service reads `.env`, so this one line covers all nine.
3. **Website:** in GitHub, go to **Settings → Secrets and variables → Actions → Variables** and add `VITE_SENTRY_DSN` with the React project's DSN. A browser DSN is public by design. The next website deploy turns reporting on.
4. In each Sentry project, add an alert rule: "a new issue is created" → email.

## 2. Uptime

Use a free UptimeRobot account (or any uptime checker). Create these monitors, at a 5-minute interval, alerting by email:

| Name | URL | Type |
|---|---|---|
| Website | `https://verdyx.dev` | HTTP(s) |
| API | `https://api.verdyx.dev/health` | Keyword `healthy` |
| API via website | `https://verdyx.dev/api/v1/health` | Keyword `healthy` (catches a broken Cloudflare proxy) |
| API ready | `https://api.verdyx.dev/ready` | HTTP(s), status 200 (fails if the database or Redis is down) |

## 3. Database backups

Neon keeps a short restore window of its own. `.github/workflows/db-backup.yml` adds an independent copy every night at 02:47 IST, using `scripts/backup/neon-backup.sh`. For each of the 9 databases it:
1. dumps it;
2. **restores it into a scratch Postgres to prove the dump works**;
3. encrypts it with AES-256;
4. uploads it to R2.

It keeps 30 days of copies. If any database fails, the run fails and GitHub emails you.

**Set up**
1. **Bucket:** in Cloudflare, go to **R2** and create a bucket `verdyx-backups`. Then **Manage R2 API Tokens** → create a token with *Object Read & Write* on that bucket only. Note its access key ID, secret access key, and the S3 endpoint `https://<account-id>.r2.cloudflarestorage.com`.
2. **Database URL:** in Neon, go to **Connect**, turn **Connection pooling off** (`pg_dump` needs the direct host), and copy the URL. Remove the database name and everything after it, leaving `postgres://user:password@ep-….neon.tech`.
3. **Passphrase:** make a long random one and **store it in your password manager**. Without it the backups can't be decrypted.
4. In GitHub, go to **Settings → Secrets and variables → Actions** and add:
   - **Secrets:** `BACKUP_PG_BASE_URL`, `BACKUP_PASSPHRASE`, `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY`
   - **Variables:** `BACKUP_S3_BUCKET` (`verdyx-backups`) and `BACKUP_S3_ENDPOINT`
5. **First run:** go to **Actions → Database backup → Run workflow**. It should end with "all databases backed up and verified".

**Restore** one database:
```bash
aws s3 cp s3://verdyx-backups/pg/<date>/<db>.dump.enc . --endpoint-url "$ENDPOINT"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in <db>.dump.enc -out <db>.dump
pg_restore --no-owner --no-acl -d "<target database url>" <db>.dump
```
Restore into a new Neon branch first, check it, then point the services at it.
