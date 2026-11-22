# Deploying Verdyx for $0 — Cloudflare Pages + Google Cloud always-free VM

This is the replacement for the dead AWS deployment. It runs the **full site**,
always-on, with no cold starts, for **$0/month indefinitely**.

Why this shape rather than a single VM like before: the stock `docker-compose.yml`
needs ~6-8 GB of RAM, and no free tier gives you that. Instead the memory-hungry
pieces move to managed free tiers that don't consume VM memory at all, and what
remains — nine small Rust binaries — fits in 1 GB.

## Architecture

```
Browser
   │
   ├── https://verdyx.pages.dev ──────────► Cloudflare Pages (free, unlimited bandwidth)
   │                                          React SPA, static assets
   │
   └── /api/* ──► Pages Function ──────────► https://verdyx-api.duckdns.org
                  functions/api/[[path]].ts       │  (GCP e2-micro, always free)
                                                  │
                                                  ▼
                                                Caddy (auto-TLS)
                                                  │
                                                api-gateway ──► 8 downstream Rust services
                                                  │
                                     ┌────────────┼────────────┐
                                     ▼            ▼            ▼
                                Postgres      Redis        Cloudflare R2
                               (on-box,     (on-box,      (10 GB free,
                                tuned)       ~15 MB)       S3-compatible,
                                                           nightly backups)
```

### What runs where, and why

| Piece | Home | Reason |
|---|---|---|
| React SPA | Cloudflare Pages | Free, unlimited bandwidth, never sleeps. Also means almost no traffic crosses the VM, keeping GCP egress inside the free 1 GB/month. |
| `/api/*` proxy | Pages Function | Keeps API same-origin with the app. `queryClient.ts` sends a `Bearer` token from `localStorage` — no cookies — so there is nothing to configure for cross-origin auth. |
| 9 Rust services | GCP e2-micro | ~50 MB each. Always on. |
| Postgres | **On the VM** | Neon's free tier was used first, but its monthly compute allowance ran out (nine always-connected services keep it awake) and every service crash-looped. A tuned container costs ~60-120 MB instead. Backed up nightly to R2; see [postgres-on-vm.md](../operations/postgres-on-vm.md). |
| Redis | **On the VM** | The `redis` crate is compiled without a TLS feature (`backend/Cargo.toml:28`), so it *cannot* speak `rediss://`. Upstash and every other managed Redis are therefore out. Capped at 64 MB, which is cheap enough that this doesn't matter. |
| File storage | Cloudflare R2 | 10 GB free. S3-compatible, and `s3_client.rs` already accepts an endpoint override with path-style addressing — config only, no code change. |
| ClamAV | **Disabled** | Its signature database alone wants ~1.5 GB, more than the whole VM. `ENABLE_CLAMAV=false`; the analyzer skips itself cleanly. |

### Memory budget

| | |
|---|---|
| 9 Rust services @ ~50 MB | ~450 MB |
| Postgres (tuned, capped at 256 MB) | ~60-120 MB |
| Redis (capped) | ~20 MB |
| Caddy | ~20 MB |
| Watchtower | ~15 MB |
| Docker daemon + OS | ~200 MB |
| **Total** | **~800 MB of 1024 MB** |

Tight but workable, and the bootstrap script adds 3 GB of swap so a spike
degrades into a slow request instead of an OOM kill.

---

## Part 1 — Frontend on Cloudflare Pages (15 min, no card)

Do this first. It is zero-risk, needs no card, and gets a public HTTPS URL up
immediately. The app degrades to empty states until the backend is attached, so
it looks unfinished-but-honest rather than broken.

Follow [`cloudflare-pages.md`](./cloudflare-pages.md). The settings that matter:

| Setting | Value |
|---|---|
| Root directory | `frontend` |
| Build command | `npm run build` |
| Build output directory | `dist/public` |
| `NODE_VERSION` env var | `22` |

You now have `https://<project>.pages.dev`. Leave `API_GATEWAY_URL` unset for
now — you'll set it in Part 6.

---

## Part 2 — Managed data tier (20 min, no card except R2)

### Postgres

Postgres runs in a container on the VM; nothing to sign up for. Set
`POSTGRES_PASSWORD` in `.env` (Part 5) and the first start creates the nine
databases. Backups need the R2 bucket below; see
[postgres-on-vm.md](../operations/postgres-on-vm.md).

### Cloudflare R2 (file storage)

R2 requires a card on file even on the free tier (10 GB, no egress fees). If
you'd rather not, **Supabase Storage** (1 GB free, no card) is also
S3-compatible and works with the same variables.

1. Cloudflare dashboard → **R2** → create buckets `verdyx-submissions` and
   `verdyx-avatars`. **Create them by hand** — the startup path tries to create
   a missing bucket, and an Object Read/Write token isn't allowed to.
2. **Manage R2 API Tokens** → create a token with *Object Read & Write*.
3. Note the Access Key ID, Secret Access Key, and the S3 endpoint
   (`https://<account-id>.r2.cloudflarestorage.com`).
4. For avatars to display, enable the `verdyx-avatars` public r2.dev URL and use
   it as `S3_PUBLIC_URL`.

---

## Part 3 — The VM (20 min)

### Create it

Free-tier rules are strict — **all four** of these must hold or you get billed:

- Machine type **`e2-micro`** (not `e2-small`)
- Region **`us-west1`**, **`us-central1`**, or **`us-east1`** only
- Boot disk **≤ 30 GB**, type **`pd-standard`** (not `pd-balanced`, the console default)
- Exactly **one** such instance on the account

Via the console (Compute Engine → Create instance), or:

```sh
gcloud compute instances create verdyx \
  --project=<YOUR_PROJECT> \
  --zone=us-east1-b \
  --machine-type=e2-micro \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-standard \
  --tags=http-server,https-server
```

### Open the firewall

GCP filters at the VPC, not on the host:

```sh
gcloud compute firewall-rules create verdyx-web \
  --allow=tcp:80,tcp:443 \
  --target-tags=http-server,https-server \
  --source-ranges=0.0.0.0/0
```

Port 80 must stay open — Caddy needs it for Let's Encrypt renewal, not just for
redirects.

### Reserve the IP

An ephemeral IP changes on stop/start and breaks your DNS. VPC network →
**IP addresses** → promote the instance's IP to static. A static IP attached to
a *running* instance is free; one left unattached is billed, so don't reserve a
spare.

### Set the billing guard — do this today

This is what killed the last deployment. Billing → **Budgets & alerts** → create
a budget of **$1** with alerts at 50%/90%/100% to your email. It won't stop
charges by itself, but you'll know within a day rather than at account
suspension.

### Bootstrap

```sh
gcloud compute ssh verdyx --zone=us-east1-b
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/deep60/Verdyx/main/scripts/deployment/gcp-bootstrap.sh)"
```

This adds swap, tunes the kernel for a small box, installs Docker, caps log
growth (a full 30 GB disk wedges Docker), and clones the repo to `/opt/verdyx`.

---

## Part 4 — DNS

The API needs a public hostname for its certificate. Reuse DuckDNS:

1. <https://duckdns.org> → add/update a domain, e.g. `verdyx-api`, pointing at
   the VM's static IP.
2. Keep it fresh on the VM:

```sh
echo 'url="https://www.duckdns.org/update?domains=verdyx-api&token=<TOKEN>&ip="' | sudo tee /opt/duckdns.sh
sudo chmod 700 /opt/duckdns.sh
sudo sed -i '1i #!/bin/sh\ncurl -k -o /var/log/duckdns.log -K -' /opt/duckdns.sh
( sudo crontab -l 2>/dev/null; echo "*/5 * * * * /opt/duckdns.sh >/dev/null 2>&1" ) | sudo crontab -
```

---

## Part 5 — Start the stack

```sh
cd /opt/verdyx
sudo cp .env.gcp.example .env
sudo chmod 600 .env
sudo nano .env          # fill every <<FILL>> value
```

Check the config before starting anything — a Caddyfile error means no TLS and
no API, and it's much easier to see here than in a crash loop:

```sh
sudo docker compose -f docker-compose.gcp.yml config >/dev/null && echo "compose OK"
sudo docker run --rm -v /opt/verdyx/infrastructure/caddy/Caddyfile.api:/etc/caddy/Caddyfile \
  caddy:2.9-alpine caddy validate --config /etc/caddy/Caddyfile
```

Then bring it up:

```sh
sudo docker compose -f docker-compose.gcp.yml up -d
```

Watch it settle — Rust services take ~40 s to pass their first health check:

```sh
sudo docker compose -f docker-compose.gcp.yml ps
sudo docker stats --no-stream
sudo docker compose -f docker-compose.gcp.yml logs -f api-gateway
```

Verify from your laptop:

```sh
curl https://verdyx-api.duckdns.org/_edge/health          # -> ok
curl https://verdyx-api.duckdns.org/api/v1/health/live    # -> gateway JSON
```

The first HTTPS request may take ~30 s while Caddy obtains the certificate.

---

## Part 6 — Connect frontend to backend

Cloudflare Pages → your project → **Settings → Environment variables**:

```
API_GATEWAY_URL = https://verdyx-api.duckdns.org
```

Redeploy. `functions/api/[[path]].ts` picks it up and forwards every `/api/*`
call, normalizing paths to the gateway's `/api/v1/…` form.

Then set `CORS_ALLOWED_ORIGINS` and `FRONTEND_URL` in the VM's `.env` to your
Pages URL and restart the gateway:

```sh
sudo docker compose -f docker-compose.gcp.yml up -d api-gateway
```

Register an account on the live site to confirm the whole path works.

---

## Continuous deployment

Already wired, and it carries over from the AWS setup unchanged:

```
push to main → deploy.yml builds + pushes ghcr.io/deep60/verdyx-<svc>:latest
             → Watchtower on the VM polls every 5 min → pulls → rolling restart
```

Watchtower is outbound-only, so no inbound access, SSH keys, or GitHub secrets
are needed. It watches only the nine app containers; Redis and Caddy are left
alone deliberately.

**You do not need Docker on your Mac.** Images are built by GitHub-hosted
runners (`runs-on: ubuntu-latest`) and pushed to GHCR. Locally you need only
`git`, `ssh`, and a browser.

Manual deploy, if you ever need it:

```sh
cd /opt/verdyx && sudo docker compose -f docker-compose.gcp.yml pull && \
  sudo docker compose -f docker-compose.gcp.yml up -d
```

---

## Operating a 1 GB box

**Check memory first when anything misbehaves.** `docker stats --no-stream`,
then `free -h`. A container stuck restarting is usually an OOM kill:

```sh
sudo dmesg | grep -i "killed process"
```

If one service is consistently the problem, raise its `mem_limit` in
`docker-compose.gcp.yml` and lower another's — the limits are caps, not
reservations, so the total is allowed to exceed 1 GB.

**Keep `RUST_LOG=warn`.** On a shared-core VM, log volume is real CPU and real
disk. Raise to `info` only while debugging, then put it back.

**Don't enable the `monitoring` profile.** Prometheus and Grafana together want
more memory than the entire application. Use `docker compose logs` and
`docker stats`.

---

## If you outgrow this

The images are already **multi-arch** (`deploy.yml:409` builds
`linux/amd64,linux/arm64`), so moving is just re-pointing DNS:

- **Oracle Always Free (4 OCPU / 24 GB ARM)** — vastly more headroom, still $0,
  and runs the *entire* stock stack including ClamAV and local Postgres. Your
  signup failed before; it commonly does on the first try. Retry with a
  different browser in incognito, a different region, and a credit card rather
  than a debit/RuPay card. Runbook: [`oracle-cloud.md`](./oracle-cloud.md).
- **Any $5/month VPS** (Hetzner, DigitalOcean) with 4 GB — the stock
  `docker-compose.yml` works as-is.
