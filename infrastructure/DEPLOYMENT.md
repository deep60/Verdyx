# Verdyx — Deployment Architecture (authoritative)

> This document is the **single source of truth** for how Verdyx is deployed.
> If anything else in `infrastructure/` disagrees with this file, this file wins.

## TL;DR

- **Launch model (what CI actually deploys): Docker Compose on a single VM.**
  - The deploy target is the **root [`docker-compose.yml`](../docker-compose.yml)**, pulled onto the
    server at `/opt/verdyx` by [`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml).
  - App tier (10 Rust services + frontend + nginx) runs as containers on one host.
- **Data tier: AWS managed services (RDS PostgreSQL + ElastiCache Redis).**
  - Provisioned by [`terraform/`](./terraform). The app connects to them over the VPC via
    `DATABASE_URL` / `REDIS_URL` — it does **not** self-host Postgres/Redis in production.
- **Kubernetes / EKS / Helm is Phase 2 (not live).**
  - The manifests under [`kubernetes/`](./kubernetes) and the EKS module in Terraform are a
    *future* scale-out path. **Nothing in CI deploys to Kubernetes today.** Do not treat those
    manifests as the running production system.

## Why one model

We previously carried two parallel, contradictory deployment stories:
compose-on-a-VM (wired into CI) **and** EKS/k8s/Helm (provisioned but never deployed to by CI).
For launch we commit to the compose path because it is already automated, cheap, and operable by a
small team. EKS becomes the documented Phase-2 upgrade for HA/autoscaling once traffic justifies it.

## Topology (launch)

```
                 ┌─────────────────────────── AWS VPC ───────────────────────────┐
   GitHub        │                                                                │
   Actions ──SSH─┤  App VM (/opt/verdyx)                RDS PostgreSQL (managed)   │
   (deploy.yml)  │   docker compose up -d                per-service databases:    │
                 │   ├─ api-gateway  ─┐                  verdyx_gateway, _users,   │
                 │   ├─ user-service  │  DATABASE_URL ─▶ _analysis, _bounty,        │
                 │   ├─ analysis-…    │                  _submissions, _consensus,  │
                 │   ├─ … (10 svcs)  ─┘                  _payments, _reputation,    │
                 │   ├─ frontend                          _notifications            │
                 │   └─ nginx (TLS)                                                 │
                 │        │                              ElastiCache Redis (managed)│
                 │        └──────────── REDIS_URL ──────▶                           │
                 └────────────────────────────────────────────────────────────────┘
                          │
                    verdyx.io (prod) / staging.verdyx.io (staging)
```

## The deploy pipeline (`deploy.yml`, `main` branch)

1. **detect-changes** — only rebuild/redeploy services whose files changed (shared-crate change ⇒ all).
2. **test-frontend / test-backend** — full CI gates (see `rust.yml`, `frontend-ci.yml`).
3. **security-scan** — `cargo audit` + `npm audit` (blocking on vulnerabilities) + Trivy (reporting).
4. **smoke-test** — compose-up the world, probe `/health`.
5. **build-and-push** — per-service Docker images → Docker Hub.
6. **deploy** — SSH to the VM →
   1. `git pull origin main`
   2. **ensure per-service databases exist on RDS** (`scripts/deployment/ensure-databases.sh`)
   3. `docker compose pull && docker compose up -d` (each service applies its own
      `sqlx::migrate!` migrations at startup against its RDS database)
   4. health check → **rollback on failure** (`scripts/deployment/rollback.sh`)

Staging is the same flow on the `develop` branch → `staging.verdyx.io`.

## Database ownership

- Each microservice **owns** its schema under `backend/<service>/migrations/` and applies it at
  startup via `sqlx::migrate!`. This is the single source of truth for schema.
- Each service uses its **own database** on the shared RDS instance (`verdyx_<service>`).
- `scripts/deployment/ensure-databases.sh` creates those databases + required extensions on RDS
  (RDS has no `initdb` hook, unlike the self-hosted dev Postgres which uses
  `database/init/01-init-databases.sql`).
- Drift check: `scripts/maintenance/check-migrations.sh`.

## Secrets

Production secrets are **not** committed. They are provisioned onto the VM's `/opt/verdyx/.env`
out of band (see `scripts/maintenance/generate-prod-secrets.sh` and the Ansible `verdyx` role).
No service holds an on-chain signing key: marketplace transactions are signed in each
person's own wallet.

## Phase 2 (post-launch, not live)

- Promote the app tier from compose-on-VM to **EKS** (Terraform `eks` module already defined).
- Deploy via **Helm** (`kubernetes/helm/`) with the existing manifests (HPA, ingress, cert-manager).
- Zero-downtime rolling deploys + autoscaling replace the current brief-downtime `compose up`.
