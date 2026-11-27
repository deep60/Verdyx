# Plans and quotas

Every team is on a plan. **Free** is where every team starts, with the
limits Verdyx has always had. **Team** and **Enterprise** raise them. There's
no checkout yet: a Verdyx administrator moves a team to another plan.

| | Free | Team | Enterprise |
|---|---|---|---|
| Scans per person | 10 a minute, 100 a day | 60 a minute, 2,000 a day | 300 a minute, 20,000 a day |
| Team scans per month | No limit | 50,000 | No limit (or as agreed) |
| Members and open invitations | 50 | 200 | 1,000 |
| Active team API keys | 10 | 50 | 200 |
| Storage connections | 5 | 10 | 25 |

An administrator can also set any of these for one team (an Enterprise
contract, say); the team's page then says **Custom limits**.

## How the limits apply

- **Per-person limits** count every scan someone starts, signed in with a
  session or an API key. Someone in a Team or Enterprise team gets the best
  of their teams' plans for all their scans. A team API key gets its team's.
  Signed-out scans count per IP address, at Free's limits. Free's limits can
  be changed with `SCAN_RATE_LIMIT_PER_MINUTE` and `SCAN_RATE_LIMIT_PER_DAY`;
  paid plans never fall below them.
- **Team scans per month** counts the scans saved to the team (file and URL
  uploads, emails, and files from connected storage) in the calendar month,
  UTC. It starts again on the 1st. When it's used up, scans into the team
  are refused until then, and connected storage waits, picking up where it
  left off. Scans people save to themselves aren't counted.
- **Members**, **team keys** and **storage connections** are checked when
  someone invites a person, makes a key or connects a bucket. Nothing already
  there is removed when a team moves to a smaller plan; the team just can't
  add more until it's under the limit.

Going over a limit returns `429` (scans) or `409` (members, keys, storage),
with a message saying which limit:

```json
{
  "error": "QUOTA_EXCEEDED",
  "message": "This team has used its 50000 scans for the month. The count starts again on 1 December. Ask Verdyx about a higher limit.",
  "limit": 50000,
  "resets_at": "2026-12-01T00:00:00Z",
  "retry_after_seconds": 302400,
  "status": 429
}
```

## Seeing usage

The team page's **Settings** tab shows the plan, the month's scans, and how
many members, keys and storage connections the team has against its limits.

| Request | Who | What it returns |
|---|---|---|
| `GET /api/v1/orgs/{id}/usage` | any member | `plan`, `custom`, `limits`, `usage` (`scansThisMonth`, `seats`, `teamKeys`, `storageConnections`), `periodStart`, `resetsAt` |
| `GET /api/v1/users/me/usage` | you | your best `plan`, your per-person `limits`, your scans in the last 24 hours, and your teams' plans |

## Changing a team's plan (administrators)

These need a Verdyx administrator's own session; API keys can't use them.
Each change is written to the team's activity log.

```bash
# Find the team
curl -s "https://api.verdyx.dev/api/v1/admin/teams?q=acme" -H "Authorization: Bearer $SESSION"

# Move it to Team
curl -s -X PUT "https://api.verdyx.dev/api/v1/admin/teams/$TEAM/plan" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  -d '{"plan": "team"}'

# Enterprise with custom limits
curl -s -X PUT "https://api.verdyx.dev/api/v1/admin/teams/$TEAM/plan" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/json" \
  -d '{"plan": "enterprise", "overrides": {"seats": 5000, "teamScansPerMonth": 2000000}}'
```

`overrides` replaces the team's earlier overrides; leave it out to go back to
the plan's own limits. Its fields are `scansPerMinute`, `scansPerDay`,
`teamScansPerMonth`, `unlimitedMonthlyScans` (`true` for no monthly limit),
`seats`, `teamKeys` and `storageConnections`. `GET /admin/teams/{id}/plan`
shows a team's plan, overrides and usage.
