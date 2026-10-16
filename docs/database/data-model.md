# Data model

Each service has its own Postgres database, created by `database/init/01-init-databases.sql`. Tables with the same name in different databases are not the same table. `database/postgres/migrations/` and `database/schema.sql` are legacy and are not applied.

Retention is indefinite. Nothing is deleted on a timer. Rows and objects are removed only when an account or a submission is explicitly deleted.

## Users — `verdyx_users.users` — user-service

Purpose: login identity.

Sensitive: `password_hash`, `two_factor_secret`. These are never returned by profile, account, or admin detail responses. Admin detail returns `UserPublic` only.

Access: the signed-in user, or an admin. Other users do not receive email, wallet, or credential fields from this table.

Ownership: only user-service writes this table. Account update and soft-delete write `account_audit_events` in the same database.

Retention: the row is kept after deletion so audit foreign keys remain valid. Deletion sets `is_active = false`, clears the password and wallet, and replaces username and email with `deleted_<id>` values.

## Profiles and settings — user-service

`user_profiles`, `user_settings`, `kyc_verifications`.

Sensitive: KYC document numbers and document URLs. Not included in public profile responses.

Ownership: user-service. Cascade when the user row is removed. Soft-delete does not remove the user row, so KYC rows remain and stay admin-only.

## Audit — `verdyx_users.account_audit_events` — user-service

Purpose: who changed identity or deleted an account, and when.

Sensitive: the `detail` JSON must not store passwords, tokens, or raw document numbers.

Access: not exposed on user-facing routes. Operators read it in the user database.

Retention: indefinite. Not removed by account deletion.

## Submissions — `verdyx_gateway.submissions` — API gateway

Purpose: a file or URL a user asked the dashboard to scan. This is the row `POST /api/v1/submissions/file` creates.

Sensitive: `original_filename`, `url`, `file_path`, `description` inside `metadata`. `file_path` is an object-storage key and is not part of the list response.

Access: `GET /api/v1/submissions` and `GET /api/v1/submissions/:id` require the caller’s JWT and `submitter_id = caller`. A missing id and another user’s id both return 404. Analyses and consensus for that id use the same check.

Ownership: the gateway inserts the row and the analysis worker updates `analysis_status`, `is_malicious`, `confidence_score`, and `metadata.last_error`. Submission-service has a different `submissions` table in `verdyx_submissions` and must not be treated as this queue.

Retention: kept until the owner deletes the submission or deletes the account. Account deletion deletes these rows and queues each `file_path` on Redis `artifact_deletions`.

Index: `(submitter_id, created_at DESC)` from `20261008000000_submission_owner_index.sql`.

## Engine results — two stores

`verdyx_analysis.engine_analysis_results` — analysis-engine. Full scan JSON for `POST /analyze/*`. Not user-scoped; do not put it on a user route without an ownership join.

`verdyx_gateway.analysis_results` — per-engine rows for a gateway submission. `submission_id` references `submissions(id)` and is removed with the submission. The worker replaces rows for a submission before inserting again, so a retry does not duplicate them.

Sensitive: detection metadata can include matched rule names. Return it only after the submission ownership check.

## Findings

There is no separate findings table. A finding is a detection inside an analysis result (`verdict`, `confidence`, categories, metadata). Same ownership and retention as the parent analysis row.

## Votes — consensus-service and bounty-manager

`verdyx_consensus.consensus_submissions`: one vote per `(bounty_id, engine_id)`. Unique constraint prevents a retry from inserting a second vote for the same engine.

`verdyx_consensus.consensus_vote_commits`: commit-reveal material. The commitment is not the vote. Do not log salts.

`verdyx_bounty.submissions`: an analyst verdict on a bounty, not a user’s file upload. Unique per bounty and engine where the schema says so. Cascade-deletes with the bounty.

Access: bounty and consensus reads are platform threat-intel, not a user’s private upload. Do not use those tables to answer `GET /api/v1/submissions/:id`.

## Bounties — bounty-manager and gateway

`verdyx_bounty.bounties` is the bounty-manager record (creator, reward, artifact hash, status).

`verdyx_gateway.bounties` is the gateway copy used by dashboard bounty routes. They are not kept in sync by a foreign key. Do not add a cross-database foreign key.

Sensitive: creator identity and reward amounts. Public list routes may show title and status. Wallet keys are not stored here.

## Other audit-like records

`verdyx_consensus.verdict_grades` and `consensus_disputes` record how a consensus result was graded or challenged. Retain indefinitely. They are not user-profile data.

Payment and notification tables (`verdyx_payments`, `verdyx_notifications`) hold payout state and delivery addresses. Email addresses in notification rows are sensitive and stay inside that service.

## Objects

Uploaded samples live in S3/MinIO under the key in `submissions.file_path`. The analysis-engine worker deletes keys from `artifact_deletions`. A failed delete is moved to `artifact_deletions:dead` and does not block scans.

Explicit deletion is the only deletion. There is no age-based purge of submissions, artifacts, analysis results, votes, bounties, or audit rows.
