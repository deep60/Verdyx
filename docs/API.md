# Verdyx API Guide

This guide documents the currently implemented API gateway surface at `backend/api-gateway`.

## Base URLs

- Local: `http://localhost:8080/api/v1`
- Production: `https://api.verdyx.dev/api/v1`

## Clients

Rather than calling the routes by hand, you can use:

- **The `verdyx` command and JavaScript/TypeScript SDK**: [`sdk/typescript`](../sdk/typescript)
- **The Python SDK**: [`sdk/python`](../sdk/python)
- **The GitHub Action**: [`action`](../action)
- **Webhooks**, to have results pushed to you: [webhooks.md](api/webhooks.md)
- **Splunk and Microsoft Sentinel**, to send events into your SIEM: [splunk.md](integrations/splunk.md), [sentinel.md](integrations/sentinel.md)
- **Similarity search**, to find variants of a file by fuzzy hash: [similarity.md](api/similarity.md)
- **Privacy**, where files go and who can open a report: [privacy.md](privacy.md)
- **Single sign-on and provisioning** with Okta, Microsoft Entra ID and other identity providers: [sso.md](integrations/sso.md)
- **Email scanning**, of attachments and links, including a phishing-report mailbox: [email.md](integrations/email.md)
- **Cloud storage scanning** of Amazon S3, Cloudflare R2 and Google Cloud Storage buckets: [cloud-storage.md](integrations/cloud-storage.md)

They all scan the same way:
1. `POST /submissions/file`, a multipart form with `file`, or `url` for a URL, plus optional `description`, `organizationId` and `priority`. An email can also be sent raw, as the body of `POST /submissions/email`.
2. Poll `GET /submissions/{id}` until `analysisStatus` is `completed` or `failed`.
3. Read the verdict from `GET /submissions/{id}/consensus` and each engine's result from `GET /submissions/{id}/analyses`.

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

Bounties live on the BountyManager contract. People post, stake on, resolve
and withdraw from them in their own wallets on the website; the server holds
no signing key and sends no transactions. `GET /chain/bounties` lists the
indexed bounties for a file or URL (see [Bounties on a file or URL](#bounties-on-a-file-or-url)).

These older routes read the off-chain bounty records from before the
marketplace moved on-chain. They are read-only:

- `GET /bounties`
- `GET /bounties/:bounty_id`
- `GET /bounties/:bounty_id/stats`
- `GET /bounties/active`
- `GET /bounties/completed`

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
| `retrohunt.started` | a hunt was queued (`details.rules`) |
| `livehunt.created`, `livehunt.updated`, `livehunt.deleted` | a live hunt was saved (`details.rules`), turned on or off or edited (`details.enabled`, `details.ruleChanged`), or removed |
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

## Retrohunt

Run a YARA rule over past uploads, on the server with real YARA (the analysis engine must be built with `--features yara-engine`, as the production image is).

| Request | What |
|---|---|
| `POST /retrohunts` `{"rule": "...", "teamId": null}` | Queue a hunt over your own uploads, or a team's (`teamId`, any member). `201` with the job id. One hunt at a time (`409`), 20 a day (`429`) |
| `GET /retrohunts` | Your last 50 hunts: status, progress (`filesTotal`, `filesScanned`, `filesFailed`), `matches`, `ruleNames` |
| `GET /retrohunts/{id}` | One hunt with its rule and `results`: each matching scan (`submissionId`, file name or URL, SHA-256) and the rules that matched. Scans you can no longer see are left out |
| `DELETE /retrohunts/{id}` | Cancel a queued or running hunt, or remove a finished one |

Rules are checked before they're queued:
- at most 64 KB and 50 rules;
- no `include`, which the compiler also refuses;
- `import` only of `pe`, `elf`, `math`, `hash`, `dotnet`, `time` and `string`.

A rule that doesn't compile ends as `failed`, with the compiler's message.

Each file gets 10 seconds. A hunt covers at most 5,000 files and runs for at most 15 minutes. Only stored files are searched, and those are kept for 30 days. API keys need the `scan` scope; team keys can't hunt.

## Live hunts

Save a YARA rule to run, with real YARA, on every new upload in its scope, and see each file it matches. Each hunt covers either:
- your own uploads, or
- a team's uploads (`teamId`), for as long as you're a member.

Rules follow the same rules as retrohunt.

| Request | What |
|---|---|
| `POST /livehunts` `{"name": "...", "rule": "...", "teamId": null}` | Save a hunt. `201` with the hunt. Up to 10 turned on (`409`) and 25 in all |
| `GET /livehunts` | Your hunts: `enabled`, `matches`, `unseen`, `lastMatchAt`, `lastError`, `ruleNames` |
| `GET /livehunts/{id}` | One hunt with its `rule` and latest 200 `results`. Each result has `submissionId`, file name or URL, SHA-256, the rules that matched, `matchedAt`, `seen` and `isMalicious`. Scans you can no longer see are left out |
| `PATCH /livehunts/{id}` `{"name"?, "rule"?, "enabled"?}` | Rename, replace the rule or turn the hunt on or off. A new rule clears `lastError` |
| `POST /livehunts/{id}/seen` | Mark its matches as seen |
| `DELETE /livehunts/{id}` | Remove it and its matches |

How hunts run:
- **When:** after each uploaded file or email (not URL pages) is loaded, before the other engines run.
- **Time limits:** each hunt gets 5 seconds per file, and all hunts together get 20 seconds per upload.
- **Anonymous uploads** are in nobody's scope.
- **A rule that doesn't compile** turns its hunt off, with the compiler's message in `lastError`.
- **Matches** are recorded once per hunt and file.
- **API keys** need the `write` scope to change hunts and `read` to list them. Team keys can't use hunts.

## Marketplace network

`GET /api/v1/chain` (public) tells the website which network and contracts the
marketplace uses. People sign every marketplace transaction in their own
wallet; the server never holds their tokens.

```json
{
  "enabled": true,
  "chainId": 84532,
  "chainName": "Base Sepolia",
  "nativeCurrency": "ETH",
  "rpcUrl": "https://sepolia.base.org",
  "explorerUrl": "https://sepolia.basescan.org",
  "contracts": {
    "threatToken": "0x…", "bountyManager": "0x…", "reputationSystem": "0x…",
    "threatFaucet": "0x…"
  }
}
```

`enabled` is false (and `contracts` null) until the contract addresses are
configured. `rpcUrl` is `PUBLIC_CHAIN_RPC_URL` or the network's public
endpoint, never the server's own `BLOCKCHAIN_RPC_URL`.
`threatFaucet` (`THREAT_FAUCET_ADDRESS`) hands out test THREAT; it is null
when unset and always null on a mainnet.

### Bounties on a file or URL

`GET /api/v1/chain/bounties?artifact=<SHA-256 or URL>` (public) lists the
bounties posted on one file or URL, newest first, at most 20. Matching ignores
case and surrounding spaces.

```json
{
  "indexed": true,
  "bounties": [
    {
      "id": 1, "creator": "0x…", "artifactHash": "d5fb…", "artifactType": "file",
      "description": "…", "reward": "40000000000000000000", "totalStaked": "0",
      "deadline": 1795028842, "status": 0, "consensusVerdict": 0,
      "analysisCount": 0, "createdAt": 1795021643
    }
  ]
}
```

- `reward` and `totalStaked` are in THREAT's smallest unit (18 decimals), as strings.
- `deadline` and `createdAt` are Unix seconds.
- `status`: 0 open, 1 in review, 2 completed, 3 cancelled, 4 disputed.
- `consensusVerdict`: 0 none, 1 benign, 2 malicious, 3 suspicious.

This reads the gateway's copy of the chain, which an indexer refreshes every
30 seconds (`CHAIN_INDEX_INTERVAL_SECS`), so a new bounty can take that long to
appear. `indexed` is false when the marketplace isn't configured. The contract
is the source of truth: the bounty page reads it directly.

## Threat feed (STIX 2.1 / TAXII 2.1)

Scans that end malicious or suspicious are published as STIX 2.1 `indicator`s:
- one for the file's SHA-256 or the URL;
- one for each URL, domain, IP address or hash an engine extracted (up to 100 per scan).

Malicious scans are `malicious-activity` (confidence 85); suspicious ones are `anomalous-activity` (50). Extracted indicators get 60.

Every indicator links to its Verdyx report (`external_references`) and is created by the Verdyx `identity`. Ids are UUID v5s of what they describe, so they stay the same between polls.

**One scan:** `GET /api/v1/submissions/{id}/stix` returns a STIX bundle (`application/stix+json;version=2.1`) to anyone who can read the scan.

**TAXII 2.1** (read-only) at the server root, `https://api.verdyx.dev/taxii2/`:

| Request | What |
|---|---|
| `GET /taxii2/` | Discovery (public) |
| `GET /taxii2/api/` | API root (public) |
| `GET /taxii2/api/collections/` | "My scans", plus one collection per team you're in (its id is the team id) |
| `GET /taxii2/api/collections/{id}/objects/` | Objects, oldest first. Takes `added_after`, `limit` (default 100, at most 500 objects), `next` and `match[type]` (`indicator`, `identity`). Sets `X-TAXII-Date-Added-First` and `-Last` |
| `GET /taxii2/api/collections/{id}/manifest/` | The same objects' ids, versions and dates |

Collections need an API key with the `read` scope: HTTP Basic (any username, the key as the password, as OpenCTI, MISP and `taxii2-client` send it), `X-API-Key`, or Bearer. A team key sees only its team's collection. Responses use `application/taxii+json;version=2.1`.

The API root URL in discovery is absolute: `PUBLIC_API_URL` if set, otherwise the request's host.

## Protected User/Wallet/Submission/Webhook Routes

- User profile: `GET /users/me`, `PUT /users/me`, `GET /users/me/stats`
- Wallet: `POST /auth/wallet/connect` links a wallet by a signed message; balances and transfers are read and signed in the wallet itself
- Submissions: `GET /submissions`, `POST /submissions`, `POST /submissions/:id/vote`
- Webhooks: CRUD and delivery routes under `/webhooks`. Events, signatures and retries: [webhooks.md](api/webhooks.md)
- Teams: `/orgs` and `/invitations` (see [Teams](#teams))
- Audit log: `GET /users/me/audit`, `GET /orgs/{id}/audit` (see [Audit log](#audit-log))
- Your data: retention, deleting scans, export (see [Your data](#your-data))
- Retrohunt: `/retrohunts` (see [Retrohunt](#retrohunt))
- Threat feed: `/taxii2/`, `GET /submissions/{id}/stix` (see [Threat feed](#threat-feed-stix-21--taxii-21))

## Minimal Example: Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@example.com",
    "password": "StrongPassword123!"
  }'
```

## Posting a bounty

Bounties are posted from the website's marketplace page, signed in your own
wallet: it approves THREAT for the BountyManager and calls `createBounty`. The
server sends no transactions. A script can do the same against the contract
directly with the addresses from `GET /api/v1/chain`.

## Related Files

- OpenAPI spec: `docs/api/openapi.yaml`
- Postman collection: `docs/api/postman/Verdyx.postman_collection.json`
- JSON examples: `docs/api/examples/`
