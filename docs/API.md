# Verdyx API Guide

This guide documents the currently implemented API gateway surface at `backend/api-gateway`.

## Base URLs

- Local: `http://localhost:8080/api/v1`
- Production: `https://api.verdyx.dev/api/v1`

## Authentication

Most write routes require JWT authentication.

Use header:

```http
Authorization: Bearer <jwt>
```

### Auth Endpoints

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `POST /auth/refresh`
- `POST /auth/verify`
- `POST /auth/verify-email`
- `POST /auth/forgot-password`
- `POST /auth/reset-password`
- `POST /auth/api-key`
- `POST /auth/wallet/connect`
- `POST /auth/wallet/disconnect`

## Health and Readiness

- `GET /health/`
- `GET /health/ready`
- `GET /health/live`
- `GET /health/metrics`

## Bounty Routes

- `GET /bounties`
- `GET /bounties/:bounty_id`
- `GET /bounties/:bounty_id/stats`
- `GET /bounties/active`
- `GET /bounties/completed`
- `POST /bounties`
- `PUT /bounties/:bounty_id`
- `POST /bounties/:bounty_id/cancel`
- `POST /bounties/:bounty_id/extend`
- `POST /bounties/:bounty_id/claim`
- `POST /bounties/:bounty_id/submit`
- `PUT /bounties/:bounty_id/finalize`

## Analysis Routes

- `GET /analysis`
- `GET /analysis/:analysis_id`
- `GET /analysis/:analysis_id/details`
- `GET /analysis/stats`
- `GET /analysis/by-bounty/:bounty_id`
- `GET /analysis/by-hash/:file_hash`
- `POST /analysis/submit`
- `POST /analysis/:analysis_id/dispute`

## Reputation Routes

- `GET /reputation/leaderboard`
- `GET /reputation/leaderboard/top`
- `GET /reputation/user/:user_id`
- `GET /reputation/badges`
- `GET /reputation/history/:user_id`
- `POST /reputation/claim-badge`

## Protected User/Wallet/Submission/Webhook Routes

- User profile: `GET /users/me`, `PUT /users/me`, `GET /users/me/stats`
- Wallet: `POST /wallet/connect`, `GET /wallet/balance`, `POST /wallet/stake`, etc.
- Submissions: `GET /submissions`, `POST /submissions`, `POST /submissions/:id/vote`
- Webhooks: CRUD and delivery routes under ` /webhooks`

## Minimal Example: Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@example.com",
    "password": "StrongPassword123!"
  }'
```

## Minimal Example: Create Bounty

```bash
curl -X POST http://localhost:8080/api/v1/bounties \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Analyze suspicious payload",
    "description": "Observed in phishing chain",
    "reward_amount": 100,
    "expires_at": "2026-04-30T23:59:59Z"
  }'
```

## Related Files

- OpenAPI spec: `docs/api/openapi.yaml`
- Postman collection: `docs/api/postman/Verdyx.postman_collection.json`
- JSON examples: `docs/api/examples/`
