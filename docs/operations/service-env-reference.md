# Per-service environment reference

Every backend service reads its configuration from environment variables.
This table lists what each service needs. In `docker-compose.yml` these are
injected from the root `.env` plus per-service overrides; in Kubernetes they
come from the per-service ConfigMap + Secrets.

## Common to all services

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SERVER_HOST` | no | `0.0.0.0` | Bind address |
| `SERVER_PORT` | no | `8080` | Internal listen port |
| `DATABASE_URL` | **yes** | — | Per-service Postgres DB |
| `REDIS_URL` | **yes** | — | Shared Redis, password-authenticated |
| `RUST_LOG` | no | `info` | Log level / filter |
| `CORS_ALLOWED_ORIGINS` | no | localhost dev origins | Comma-separated |
| `ENVIRONMENT` | no | `development` | `production` enables stricter checks |

All services expose: `GET /health`, `GET /health/live`, `GET /health/ready`,
`GET /metrics` (Prometheus text format). `/health/ready` returns 503 when the
database is unreachable.

## api-gateway

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | **yes** | ≥32 chars; gateway refuses to boot in prod with the default |
| `USER_SERVICE_URL` … `NOTIFICATION_SERVICE_URL` | yes | Downstream URLs |
| `BLOCKCHAIN_RPC_URL` | if blockchain on | RPC endpoint |
| `THREAT_TOKEN_ADDRESS`, `REPUTATION_SYSTEM_ADDRESS`, `BOUNTY_MANAGER_ADDRESS` | if blockchain on | Contract addresses |
| `CHAIN_ID` | no | Defaults to 31337 |

## user-service

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | **yes** | Must match api-gateway |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | optional | Avatar uploads; disabled if unreachable |

## submission-service

| Variable | Required | Notes |
|---|---|---|
| `SUBMISSION_SERVICE_PORT` | no | Overrides `SERVER_PORT`; compose sets 8080 |
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | **yes** | File storage |

## analysis-engine

| Variable | Required | Notes |
|---|---|---|
| `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY` | **yes** | Sample storage |
| `YARA_RULES_PATH` / `YARA_RULE_PATH` | no | Defaults to `./rules` |
| `CLAMAV_HOST` | if `ENABLE_CLAMAV` | `clamav:3310` |
| `ENABLE_CLAMAV` | no | Toggle AV scanning |
| `UPLOAD_DIR` | no | Defaults to `./temp/verdyx-uploads` |

## bounty-manager

| Variable | Required | Notes |
|---|---|---|
| `BLOCKCHAIN_RPC_URL` / `ETHEREUM_RPC_URL` | for chain reads | RPC endpoint |
| `BOUNTY_MANAGER_ADDRESS`, `THREAT_TOKEN_ADDRESS` | for chain reads | Contract addresses; `GET /withdrawals/{address}` returns 503 without them |
| `BOUNTY_MANAGER_ABI_PATH`, `THREAT_TOKEN_ABI_PATH` | for chain reads | Compiled ABI JSON |

bounty-manager holds no signing key. It no longer runs a chain sync or a
resolution keeper: anyone resolves a bounty from the website, and the gateway
indexes bounties for scan reports.

## payment-service

| Variable | Required | Notes |
|---|---|---|
| `BLOCKCHAIN_RPC_URL` | **yes** | RPC endpoint |
| `BLOCKCHAIN_CHAIN_ID` / `CHAIN_ID` | yes | Network id |
| `TREASURY_ADDRESS` | **yes** | Recorded as the payer on off-chain payment rows |
| `TOKEN_CONTRACT_ADDRESS`, `PAYMENT_CONTRACT_ADDRESS` | yes | Contract addresses |

payment-service holds no treasury key. Its routes that sent tokens (bounty
reward distribution, withdrawals, stake slashing) answer **410 Gone**: the
BountyManager contract pays rewards and settles stakes when a bounty is
resolved, and people withdraw in their own wallets.

## consensus-service

| Variable | Required | Notes |
|---|---|---|
| `CONSENSUS_THRESHOLD` | no | Default 0.7 |
| `MIN_SUBMISSIONS_REQUIRED` | no | Default 3 |

## reputation-service

| Variable | Required | Notes |
|---|---|---|
| `REPUTATION_DECAY_RATE` | no | Default 0.95 |
| `REPUTATION_UPDATE_INTERVAL` | no | Seconds; default 3600 |

## notification-service

| Variable | Required | Notes |
|---|---|---|
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM` | if `ENABLE_EMAIL` | SMTP transport |
| `WEBHOOK_TIMEOUT`, `MAX_RETRY_ATTEMPTS` | no | Webhook delivery tuning |

## Secrets hygiene

- `.env.example` contains **only placeholders** — never real values. CI and the
  smoke test generate throwaway values; production injects from a secrets
  manager (see `docs/operations/go-live-runbook.md`).
- `JWT_SECRET` must never be committed. They are
  gitignored in `.env` and templated as `CHANGE_ME` in `.env.production`.
