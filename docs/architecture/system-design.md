# System Design

## 1. Overview

Verdyx is organized around an API gateway fronting multiple domain services. The gateway handles auth, request shaping, and route orchestration while domain services own business logic and persistence boundaries.

Ownership, sync versus async calls, and the submission trace are in `service-ownership.md`. That file wins if this overview and the code disagree about who writes a table.

## 2. Core Components

### API Gateway

Responsibilities:
- JWT-based auth and request middleware.
- Public and protected route groups under `/api/v1`.
- Delegation to analysis, bounty, reputation, submission, wallet, and webhook handlers.

### Domain Services

- User Service: identity/profile/auth workflows.
- Analysis Engine: scanning and enrichment pipeline.
- Bounty Manager: bounty lifecycle and on-chain integration.
- Submission Service: analyst submissions and vote/verify workflows.
- Consensus Service: aggregation and decisioning.
- Payment Service: payout and treasury transactions.
- Reputation Service: score computation and leaderboard.
- Notification Service: outbound notification channels.

## 3. Storage and State

### PostgreSQL

Use cases:
- User, bounty, submission, payment, and reputation records.
- Transactional consistency and queryable history.

### Redis

Use cases:
- Session and token-adjacent caching.
- Rate limiting support.
- Lightweight event fan-out patterns.

### Object Storage (MinIO/S3)

Use cases:
- Uploaded artifacts and large binary payloads.

## 4. Security Boundaries

- Public endpoints: auth and health routes.
- Mixed endpoints: read routes often public, write routes protected.
- Protected endpoints: user/wallet/submission/webhook domains.
- Service-to-service trust anchored in network policy plus secrets.

## 5. Blockchain Integration

Gateway and bounty/payment domains consume configured chain RPC and contract addresses:
- Bounty Manager contract
- Threat Token contract
- Reputation System contract

Configuration is environment-driven via TOML and `.env` templates under `config/`.

## 6. Deployment Shapes

- Local dev: `docker-compose.dev.yml` (core dependencies).
- Full local stack: `docker-compose.yml`.
- Cluster rollout: manifests in `infrastructure/kubernetes`.
