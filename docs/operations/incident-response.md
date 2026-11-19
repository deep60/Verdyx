# Verdyx — Incident Response

How to detect, triage, mitigate, and learn from production incidents. This
is the companion to the
[go-live runbook](./go-live-runbook.md) and
[database rollback strategy](../database/rollback-strategy.md).

## Severity levels

| Sev | Definition | Examples | Response |
|-----|------------|----------|----------|
| **SEV1** | Full outage or data loss / security breach | API down, Postgres down, treasury key compromise, funds at risk | Page on-call immediately, open incident channel, all-hands |
| **SEV2** | Major degradation, no data loss | Elevated 5xx, one core service crash-looping, consensus stalled | Page on-call, mitigate within the hour |
| **SEV3** | Minor / partial degradation | High latency on one endpoint, non-critical worker lagging | Handle in business hours |
| **SEV4** | Cosmetic / no user impact | Noisy alert, dashboard glitch | Backlog ticket |

When unsure, round **up**. It is cheaper to downgrade a SEV2 than to
under-respond to a SEV1.

## Roles

- **Incident Commander (IC):** owns the incident, makes the call on
  mitigations, keeps the timeline. Usually the on-call engineer.
- **Comms:** posts status updates (internal channel + status page).
- **Ops/Scribe:** runs commands the IC directs, records the timeline.

For a solo on-call, one person holds all roles — write things down as you
go so the retro is possible.

## Detection

Incidents surface through Prometheus alerts routed to Slack via
Alertmanager (see `infrastructure/kubernetes/monitoring/alerts.yaml`).
Map each alert to a first action:

| Alert | Likely cause | First action |
|-------|--------------|--------------|
| `ServiceDown` | Pod crashed / OOM / bad deploy | `kubectl -n verdyx get pods`, check recent rollout |
| `PodCrashLooping` | Bad config, failed migration, panic on boot | `kubectl -n verdyx logs <pod> --previous` |
| `HighErrorRate5xx` | Downstream failure, bad deploy, DB saturation | Check which `app` label, inspect its logs + deps |
| `HighRequestLatency` | DB slow queries, resource pressure, RPC latency | Check `PodCPUPressure` / `PodMemoryPressure`, DB load |
| `PostgresDown` | DB crash, disk full, connection exhaustion | See "Database down" below |
| `RedisDown` | Redis crash / OOM | Sessions + rate limiting degraded; restart Redis, watch memory |
| `BlockchainRpcStale` | RPC provider outage, wrong endpoint | Fail over to backup RPC, check provider status page |
| `CertificateExpiringSoon` | cert-manager not renewing | Check cert-manager logs, ACME challenge |
| `BackupMissing` | Cron / backup script failed | See "Backups failing" below |
| `PodMemoryPressure` / `PodCPUPressure` | Load spike or leak | Consider scaling replicas, then investigate root cause |

## Response workflow

1. **Acknowledge** the alert so others know it is owned.
2. **Declare** severity and open an incident channel
   (`#incident-YYYYMMDD-<short-desc>`).
3. **Assess blast radius.** Which services/users are affected? Use:
   ```bash
   kubectl -n verdyx get pods
   kubectl -n verdyx rollout status deploy/verdyx-api-gateway
   curl -sS https://api.verdyx.com/api/v1/health/ready
   ```
4. **Mitigate first, root-cause later.** Restore service before doing
   deep forensics. Prefer the fastest safe lever (rollback, scale,
   failover, feature-flag off).
5. **Communicate** at a steady cadence (every 30 min for SEV1/2 even if
   "no change").
6. **Resolve** — confirm health, confirm alerts cleared, downgrade.
7. **Retro** within 2 business days (see below).

## Common mitigations

### Bad deploy — roll back the service

```bash
# See rollout history
kubectl -n verdyx rollout history deploy/verdyx-<service>
# Roll back to the previous revision
kubectl -n verdyx rollout undo deploy/verdyx-<service>
kubectl -n verdyx rollout status deploy/verdyx-<service>
```

### Restart a wedged pod

```bash
kubectl -n verdyx delete pod <pod>        # Deployment reschedules it
# or force a rolling restart of the whole deployment:
kubectl -n verdyx rollout restart deploy/verdyx-<service>
```

### Scale under load

```bash
kubectl -n verdyx scale deploy/verdyx-<service> --replicas=<n>
```

### Database down

1. Check the pod / instance and disk:
   ```bash
   kubectl -n verdyx logs deploy/postgres --tail=200
   kubectl -n verdyx exec deploy/postgres -- df -h
   ```
2. If disk is full, free space or expand the volume before restarting.
3. If the data is corrupt or a migration went wrong, follow the
   [rollback strategy](../database/rollback-strategy.md) and, if needed,
   restore from backup:
   ```bash
   ./scripts/maintenance/restore.sh --backup backups/<TIMESTAMP> --yes
   ```
   **Restoring is destructive** — it overwrites current data. Confirm the
   backup timestamp and get IC sign-off first.

### Redis down

Sessions and rate limiting depend on Redis. On restart, users may be
logged out and rate-limit counters reset. Restart Redis, watch
`maxmemory`, and confirm services reconnect.

### Blockchain RPC stale / failing

1. Confirm with the provider's status page.
2. Fail over by updating the `*_RPC` / provider secret to a backup
   endpoint and restarting the affected services (bounty-manager,
   payment-service).
3. On-chain writes queued during the outage should retry via the
   resolution/worker paths — confirm they drain after recovery.

### Backups failing (`BackupMissing`)

```bash
# Inspect the cron output / last run
kubectl -n verdyx logs job/verdyx-backup --tail=200
# Run a manual backup to unblock
./scripts/maintenance/backup.sh
```
Root-cause the cron/permissions/storage issue before closing.

## Security incidents

Treat as **SEV1** by default.

- **Suspected key compromise (JWT signing key, DB creds, the contract
  deployer key):**
  1. Rotate the affected secret immediately in the secrets manager and
     restart consumers.
  2. For the deployer key, transfer contract ownership and roles to a fresh
     key and replace the GitHub environment value.
  3. For `JWT_SECRET`, rotating it invalidates all issued tokens — expect
     mass logout. This is acceptable during a breach.
  4. Follow the DB credential rotation runbook:
     [`postgres-password-rotation.md`](./postgres-password-rotation.md).
- **Do not** delete logs or evidence. Preserve them for forensics.
- Record who was notified and when.

## Communication templates

**Initial (internal):**
> :rotating_light: SEV<n> declared <time UTC>. Impact: <what users see>.
> IC: <name>. Investigating. Next update in 30m.

**Update:**
> SEV<n> update <time>: <what we know> / <what we've tried> / <next step>.
> Next update in 30m.

**Resolved:**
> :white_check_mark: SEV<n> resolved <time>. Root cause: <short>.
> User impact: <duration/scope>. Retro to follow by <date>.

## After the incident — retrospective

Blameless. Within 2 business days, capture:

- **Timeline** — detection → mitigation → resolution (UTC).
- **Impact** — who/what, duration, any data or funds affected.
- **Root cause** — the actual cause, not just the trigger.
- **What went well / what hurt.**
- **Action items** — each with an owner and due date. Common outputs:
  a new alert, a runbook fix, a guardrail, a test.

File the retro under `docs/operations/incidents/<date>-<slug>.md` and
link it from the incident channel.

## Quick reference

- Health: `https://api.verdyx.com/api/v1/health/live` (liveness),
  `/api/v1/health/ready` (readiness)
- Smoke test: `BASE_URL=https://api.verdyx.com scripts/test/smoke.sh --remote`
- Pods: `kubectl -n verdyx get pods`
- Logs: `kubectl -n verdyx logs deploy/verdyx-<service> --tail=200 [--previous]`
- Rollback deploy: `kubectl -n verdyx rollout undo deploy/verdyx-<service>`
- DB restore: `./scripts/maintenance/restore.sh --backup backups/<TS> --yes`
