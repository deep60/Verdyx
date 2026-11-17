# Verdyx API Guide

This guide documents the currently implemented API gateway surface at `backend/api-gateway`.

## Base URLs

- Local: `http://localhost:8080/api/v1`
- Production: `https://api.verdyx.dev/api/v1`

## Authentication

Most write routes require authentication: a session token from sign-in, or an API key.

```http
Authorization: Bearer <session token or API key>
X-API-Key: vdx_…
```

### API keys

Create keys on your profile page (**API keys** tab) or with `POST /auth/api-key` while signed in:

```json
{ "name": "SOC pipeline", "scopes": ["read", "scan"], "expires_in_days": 90 }
```

The response holds the key (`vdx_` plus 64 hex characters) once; only its SHA-256 is stored. `scopes` defaults to `["read", "scan"]`, and `expires_in_days` (1–365) is optional. An account can hold 10 active keys; a request for an eleventh returns `409`.

| Scope | Allows |
|---|---|
| `read` | GET requests |
| `scan` | Submitting files and URLs, starting analyses |
| `write` | Other changes: webhooks, bounties, votes |

A key acts as its owner, never as an admin. Whatever its scopes, it can't sign in, create, list or revoke keys, change or delete the account, manage teams, or move funds: those need a signed-in session. An unknown, revoked or expired key gets `401`; a request outside its scopes gets `403` with the reason.

List keys with `GET /users/me/api-keys` (name, prefix, scopes, created, last used, expiry) and revoke one with `DELETE /users/me/api-keys/{id}`.

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

## Teams

A team shares scans and API keys between people. Each member has one role:

| Role | See team scans | Scan into the team | Invite, remove, change roles, team keys, rename | Delete the team |
|---|:-:|:-:|:-:|:-:|
| `owner` | ✓ | ✓ | ✓ | ✓ |
| `admin` | ✓ | ✓ | ✓ (not owners; can't make owners) | |
| `member` | ✓ | ✓ | | |
| `viewer` | ✓ | | | |

A team always keeps an owner: its last owner can't leave or step down. Someone can own up to 5 teams, and a team holds up to 50 members and open invitations. A team you aren't in answers `404`.

| Request | Who | What |
|---|---|---|
| `GET /orgs` | anyone | Your teams, with your role |
| `POST /orgs` `{"name"}` | anyone | Create a team; you become its owner |
| `GET /orgs/{id}` | members | The team and its members; owners and admins also see open invitations |
| `PATCH /orgs/{id}` `{"name"}` | owner, admin | Rename |
| `DELETE /orgs/{id}` | owner | Delete. Scans go back to whoever uploaded them; keys and invitations are deleted |
| `PATCH /orgs/{id}/members/{user_id}` `{"role"}` | owner, admin | Change a role |
| `DELETE /orgs/{id}/members/{user_id}` | owner, admin, or yourself | Remove someone, or leave |
| `POST /orgs/{id}/invitations` `{"email","role"}` | owner, admin | Invite. Returns `code` once; the website link is `/teams?invite=<code>`. Valid 7 days |
| `DELETE /orgs/{id}/invitations/{invitation_id}` | owner, admin | Withdraw an invitation |
| `GET /invitations` | anyone | Open invitations to your address |
| `POST /invitations/accept` `{"code"}` or `{"id"}` | the invitee | Join. Only works signed in with the invited address; accepting by `id` also needs a verified address |
| `DELETE /invitations/{invitation_id}` | the invitee | Decline |
| `GET`, `POST /orgs/{id}/api-keys`, `DELETE /orgs/{id}/api-keys/{key_id}` | owner, admin | Team keys (same body as personal keys; 10 active per team) |

**Team scans.** Add the form field `organizationId=<team id>` to `POST /submissions/file` to save a scan to a team (owners, admins and members). Everyone in the team can then read it and its results. `GET /submissions?organization=<team id>` lists the team's scans.

**Team keys** act for the team: their scans are always saved to it, `GET /submissions` lists the team's scans, and they can read only the team's scans. They may use only `/submissions`, `/engines` and `/health`. A team key stops working when the admin who made it leaves the team or stops being an owner or admin.

When someone deletes their account, the scans they saved to teams stay with the teams. A team they alone owned passes to its longest-standing admin (or member, then viewer), or is deleted if nobody else is in it.

## Audit log

Verdyx records who did what, when and from where. Rows can't be changed, and they are deleted after 12 months (`AUDIT_RETENTION_DAYS`, default 365, minimum 30).

| Request | Who | Shows |
|---|---|---|
| `GET /users/me/audit` | you (a session, or a personal key with `read`) | What you did, and what happened to your account: failed sign-ins, reset requests, role changes made to you. Includes IP address and browser. |
| `GET /orgs/{id}/audit` | team owners and admins | Everything done in the team, including by team keys. No IP addresses or browsers. |

Both take:
- `limit`: default 50, at most 200;
- `before`: the `nextBefore` from the previous page;
- `action`: a prefix such as `team.member` (lowercase letters, dots and underscores only);
- `format=csv`: up to 10,000 events. Fields are quoted, and values starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets don't run them as formulas.

```json
{
  "events": [
    {
      "id": 812, "occurredAt": "2026-11-17T10:04:00Z", "action": "team.member.role_changed",
      "actor": {"id": "…", "username": "ana"}, "via": "session", "apiKeyId": null, "teamId": "…",
      "subject": {"id": "…", "username": "ben"}, "targetType": null, "targetId": null,
      "details": {"from": "member", "to": "viewer"}
    }
  ],
  "nextBefore": 790
}
```

`via` is `session` or `api_key`. A deleted account appears as `deleted_<id>`.

| Action | Recorded when |
|---|---|
| `auth.register`, `auth.login` | an account is created, a sign-in succeeds (`details.method`: `password`, `google`, `github`) |
| `auth.login_failed` | a wrong password for an existing account (no actor; `subject` is the account). Unknown addresses aren't recorded |
| `auth.password_reset_requested` | a reset link was asked for an existing account |
| `account.updated`, `account.deleted` | profile changes (`details.fields`), account deletion |
| `api_key.created`, `api_key.revoked` | personal keys (`details`: name, scopes, prefix; never the key) |
| `team.created`, `team.renamed`, `team.deleted` | |
| `team.member.role_changed`, `team.member.removed`, `team.member.left` | `subject` is the member |
| `team.invitation.sent`, `.withdrawn`, `.accepted`, `.declined` | |
| `team.api_key.created`, `team.api_key.revoked` | |
| `account.retention_changed`, `team.retention_changed`, `account.exported` | |
| `scan.deleted`, `scan.expired` | deleted by hand, or by retention (`via: system`, `details.count`) |
| `scan.created` | a signed-in scan (`targetId` is the submission; `teamId` when saved to a team) |

## Your data

| Request | Who | What |
|---|---|---|
| `GET /users/me/retention` | you | Your scan retention (`scanRetentionDays`: null or 30/90/180/365), plus the platform rules (`sampleRetentionDays`, `guestScanRetentionDays`) |
| `PUT /users/me/retention` `{"scanRetentionDays": 90}` | you | Delete your own scans after that many days; `null` keeps them |
| `PUT /orgs/{id}/retention` `{"scanRetentionDays": 30}` | team owners, admins | The same for the team's scans (shown as `scanRetentionDays` in `GET /orgs/{id}`) |
| `DELETE /submissions/{id}` | the scan's maker, or an owner or admin of its team | Delete a scan, its results and its file. `409` if it carries a bounty. API keys need `write` |
| `GET /users/me/export` | you (sessions only) | A JSON download of your account, scans and results, keys (never the keys themselves), teams, webhooks and activity |

A scan whose file was deleted by retention has `filePurgedAt`. Running it again answers `409`. See [docs/operations/retention.md](operations/retention.md) for the rules.

## Protected User/Wallet/Submission/Webhook Routes

- User profile: `GET /users/me`, `PUT /users/me`, `GET /users/me/stats`
- Wallet: `POST /wallet/connect`, `GET /wallet/balance`, `POST /wallet/stake`, etc.
- Submissions: `GET /submissions`, `POST /submissions`, `POST /submissions/:id/vote`
- Webhooks: CRUD and delivery routes under ` /webhooks`
- Teams: `/orgs` and `/invitations` (see [Teams](#teams))
- Audit log: `GET /users/me/audit`, `GET /orgs/{id}/audit` (see [Audit log](#audit-log))
- Your data: retention, deleting scans, export (see [Your data](#your-data))

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
