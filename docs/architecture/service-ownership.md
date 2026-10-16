# Service ownership and communication

This is the map a developer should use to trace one submission and to see who owns each piece of state. If a write is listed under one service, other services must not perform that write.

Browser traffic enters the frontend BFF (`frontend/server/routes.ts`), which rewrites `/api/...` to `/api/v1/...` and proxies to the API gateway. The gateway is the only public API. Domain services are not called by the browser.

## Submission trace

1. The dashboard posts `POST /api/submissions/file` (BFF → `POST /api/v1/submissions/file`). The gateway requires a Bearer JWT. Missing or invalid tokens return `401`.
2. The gateway persists the submission row (`analysis_status = pending`) and pushes the submission id onto the Redis list `analysis_queue`. The HTTP response returns that row. It does not wait for scanners.
3. The analysis-engine worker takes the id with `BRPOPLPUSH` onto `analysis_queue:processing`, so a crash does not drop accepted work. On startup, anything still on the processing list is moved back to `analysis_queue`.
4. The worker loads the submission, sets `analysis_status` to `analyzing`, downloads the object from S3/MinIO, and runs the in-process analyzers. YARA, ClamAV, and the ONNX model run only when those Cargo features are compiled and their runtime dependencies are present. Otherwise those engines are skipped and the built-in hash, static, heuristic, and signature analyzers still run.
5. Results are written back to the same submission row (`is_malicious`, `confidence_score`, `analysis_status = completed`) and to `analysis_results`. A retry deletes that submission's previous `analysis_results` rows before inserting, so retries do not create a second result set or a second payout. This worker does not pay bounties.
6. A Redis pub/sub event (`events:analysis_completed`) notifies websocket listeners. The client reads status with `GET /api/submissions` or `GET /api/submissions/:id`. `metadata.last_error` is the last worker diagnostic; an empty string means the last attempt succeeded.
7. Consensus, bounty payouts, and reputation are separate later steps. They are not part of this queue. A scan completing does not by itself move ETH.

Failure on the worker: the id is acknowledged off the processing list, `analysis_queue:attempts` is incremented, and the job is pushed back to `analysis_queue` while `metadata.last_error` records `attempt N/3: ...`. After 3 attempts the id is pushed to `analysis_queue:dead` and `analysis_status` becomes `failed`. A payload that is not a UUID is dead-lettered immediately and does not block the list. There is no cancellation API. The scan timeout is the analysis engine's configured analysis timeout (default 120 seconds).

## Services

### API gateway (`backend/api-gateway`, port 8080)

- Owns: public `/api/v1` routing, JWT checks, request metrics, and the gateway database used for submissions, bounties, and stats that the dashboard reads.
- Does not own: user identity. Profile and account deletion are proxied to user-service. The gateway must not `UPDATE users` for those actions.
- Inputs: HTTP `/api/v1/*`, `Authorization: Bearer`.
- Outputs: JSON. Auth routes use `{ success, data, message, timestamp }`. Other routes return the resource or `{ error, status }`.
- Dependencies: PostgreSQL, Redis (JWT blacklist and sessions), downstream HTTP services, optional chain RPC.
- Failure: downstream unreachable → `502` `{ "error": "...", "status": 502 }`. Invalid JWT on a protected route → `401`. Validation failure → `400` with `error`.

### User service (`backend/user-service`, port 8081)

- Owns: `users`, `user_profiles`, `user_settings`, KYC, and `account_audit_events` in the user database.
- Inputs: `/api/v1/auth/*` (register, login, refresh, forgot-password, reset-password are public). Profile, settings, wallet link, and `/api/v1/account` require a Bearer access token.
- Outputs: auth JSON, or `{ error, status }` from `AppError`.
- Account actions:
  - `PUT /api/v1/account` with `{ username?, email?, bio? }`. Username is 3–50 letters, numbers, or `_`. Email must contain `@` and a domain dot, and is stored lowercased. Changing email clears `email_verified`. Conflicts return `409`.
  - `DELETE /api/v1/account` soft-deletes: `is_active = false`, login material and wallet cleared, username/email anonymized, session key removed, `account.deleted` audit row written. The row is kept so foreign keys remain valid.
  - Password reset: `POST /api/v1/auth/forgot-password` then `POST /api/v1/auth/reset-password` with the emailed token. Tokens live in Redis and expire.
  - Sessions: access JWTs expire (`expires_in` from login, typically 1 hour). Refresh tokens are a separate type. Logout writes `jwt_blacklist:<token>` until the access token's own expiry. The UI drops local tokens when `/api/v1/auth/verify` is not successful.
  - Wallet: the browser signs a message and posts `POST /api/v1/auth/wallet/connect`. Disconnect is `POST /api/v1/auth/wallet/disconnect`. Linking is an identity update, not a chain transaction.
- Failure: database down → readiness `503` and handler `500` without leaking SQL. Duplicate username/email → `409`.

### Analysis engine (`backend/analysis-engine`, port 8082)

- Owns: running scanners and the analysis queue worker. Direct HTTP: `POST /analyze/file`, `/analyze/url`, `/analyze/hash`, `GET /analysis/:id`.
- Dependencies: PostgreSQL, Redis, S3/MinIO. Optional: libyara, clamd, ONNX models. URL fetches are restricted to public HTTP(S) addresses; redirects are re-checked.
- Failure: scanner errors are recorded per engine and do not abort the other engines. Queue behavior is above. Health `/health` reports which native engines were compiled in.

### Submission service (port 8084)

- Owns: analyst vote/verify workflows on its own submission tables. It is not the dashboard file-upload path. The dashboard upload is the gateway route in the trace above.
- Do not add a second writer for `analysis_status` on the gateway submission row.

### Consensus service (port 8085)

- Owns: votes, weighted consensus, commit-reveal, disputes, and delayed grading in `consensus_*` tables.
- Input: votes keyed by bounty id. Output: stored verdict, confidence, agreement. Not invoked by the analysis queue.

### Bounty manager (port 8083)

- Owns: bounty lifecycle, staking records, and the bounty-side blockchain sync. Payout creation lives here and in payment-service, not in the analysis worker.

### Payment service (port 8086)

- Owns: payout execution. Must stay idempotent on payout ids. Analysis retries must not call it.

### Reputation service (port 8087)

- Owns: score history and leaderboard reads. Scores change when consensus/bounty flows record an outcome, not when a file scan finishes.

### Notification service (port 8088)

- Owns: email, webhook, and websocket delivery. It consumes events; it is not a source of verdicts.

## Synchronous vs asynchronous

| From | To | Mode | What |
| --- | --- | --- | --- |
| Browser | Frontend BFF | Sync HTTP | All `/api/*` |
| BFF | API gateway | Sync HTTP | `/api/v1/*` |
| Gateway | User service | Sync HTTP | Auth, account, profile |
| Gateway | Analysis engine | Sync HTTP | Direct `/analyze/*` when that route is used |
| Gateway | Redis `analysis_queue` | Async list | Accepted submission ids |
| Analysis worker | PostgreSQL, S3 | Sync | Load artifact, write status and results |
| Analysis worker | Redis pub/sub | Async | `events:analysis_updated`, `events:analysis_completed` |
| Services | Kafka | Not in use | `backend/shared` Kafka client is a stub |

## Shared dependencies

| Dependency | Used by | Failure behavior |
| --- | --- | --- |
| PostgreSQL | Every service, separate databases where configured | Ready checks return 503. Requests that need the row return 500. |
| Redis | Gateway blacklist, user sessions, analysis queue, pub/sub | Queue pop errors back off 5 seconds. Login/logout still attempt the database. |
| S3/MinIO | Analysis engine, avatar uploads | Scan fails, job retries, then dead-letters. Avatar upload returns 500 if storage is unset. |
| Chain RPC | Gateway blockchain service, bounty manager, payment service | Chain calls fail closed. Scans do not depend on the chain. |
| ClamAV / libyara / ONNX | Analysis engine, feature-gated | Reported unavailable. Other engines still run. |

## API versioning and errors

- Version prefix: `/api/v1`. The BFF accepts `/api/...` and `/api/v1/...` and always forwards `/api/v1/...`.
- There is no gRPC server. Docs that mention gRPC describe a planned interface.
- Protected routes require `Authorization: Bearer <access JWT>`.
- Predictable statuses for the account and submission paths: `400` validation, `401` missing or invalid token, `403` authenticated but not allowed, `404` missing resource, `409` username or email taken, `502` downstream unavailable, `500` unexpected server error.
- Error body for those handlers: `{ "error": "human readable", "status": 400 }`.
- The UI must not display fields that this document and `docs/api-contract.md` do not list. Profile accuracy is not measured and is shown as an em dash.

## Account UI

| Control | Contract | Behavior |
| --- | --- | --- |
| Save username/email | `PUT /api/users/me` | Works. Server validates. `409` if taken. |
| Delete account | `DELETE /api/users/me` | Works. Soft-delete plus audit. UI asks for confirmation, then clears the session. |
| Forgot / reset password | `POST /api/auth/forgot-password`, `POST /api/auth/reset-password` | Implemented in user-service. Token expires in Redis. |
| Connect / disconnect wallet | `POST /api/auth/wallet/connect`, `POST /api/auth/wallet/disconnect` | Requires a signed message. Not a chain transaction. |
| Session expiry | `expires_in` on login; `GET /api/auth/verify` | Expired access tokens fail verify and the UI drops them. Refresh is `POST /api/auth/refresh`. |
