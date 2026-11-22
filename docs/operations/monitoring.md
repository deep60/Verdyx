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

Postgres runs on the VM ([postgres-on-vm.md](./postgres-on-vm.md)). Every night:

1. **20:30 UTC, on the VM:** the `pg-backup` container (`scripts/backup/vm-backup.sh`) dumps each of the 9 databases, encrypts it with AES-256 and uploads it to R2.
2. **21:17 UTC, in GitHub Actions:** `.github/workflows/db-backup.yml` (`scripts/backup/verify-backup.sh`) downloads that set and **restores every database into a scratch Postgres to prove it works**.
   - It fails if the set is missing, older than 26 hours, or doesn't restore.
   - It keeps 30 days of copies, and always the newest 7.

A failed run makes GitHub email you.

**Set up**
1. **Bucket:** in Cloudflare, go to **R2** and create a bucket `verdyx-backups`.
   - Then go to **Manage R2 API Tokens** and create a token with *Object Read & Write* on that bucket only.
   - Note its access key ID, its secret access key, and the S3 endpoint `https://<account-id>.r2.cloudflarestorage.com`.
2. **Passphrase:** make a long random one and **store it in your password manager**. Without it the backups can't be decrypted.
3. **In GitHub,** go to **Settings → Secrets and variables → Actions** and add:
   - **Secrets:** `BACKUP_PASSPHRASE`, `BACKUP_S3_ACCESS_KEY_ID`, `BACKUP_S3_SECRET_ACCESS_KEY`
   - **Variables:** `BACKUP_S3_BUCKET` (`verdyx-backups`) and `BACKUP_S3_ENDPOINT`
4. **On the VM,** put the same five values in `/opt/verdyx/.env`. See `.env.gcp.example`.
5. **First run:**
   - On the VM, run `sudo docker compose -f docker-compose.gcp.yml run --rm pg-backup now`.
   - Then go to **Actions → Database backup → Run workflow**. It should end with "backup <date> verified".

**Restore:** see [postgres-on-vm.md](./postgres-on-vm.md#restoring-later). The short version is `docker compose -f docker-compose.gcp.yml run --rm pg-backup restore <date>` into empty databases.
