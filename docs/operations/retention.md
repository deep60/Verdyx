# Data retention and deletion

What Verdyx deletes on its own, what people can delete, and how to check it works.

## Rules

The gateway runs a retention job a minute after start-up (`RETENTION_FIRST_RUN_SECS`), then daily. Each run works oldest first, in batches.

| What | When | Setting |
|---|---|---|
| A scan's uploaded file (the scan and results stay; the report says the file was deleted) | 30 days after the scan | `SAMPLE_RETENTION_DAYS` (0 = keep) |
| A scan made while signed out | after 90 days | `GUEST_SCAN_RETENTION_DAYS` (0 = keep) |
| A team's scans | 30, 90, 180 or 365 days, or never | Teams → Settings (owners and admins) |
| Someone's own scans | the same choices | Profile → Data |
| Audit log entries | after 365 days | `AUDIT_RETENTION_DAYS` (minimum 30) |
| Database backups | after 30 days | `scripts/backup/neon-backup.sh` |

Notes:
- **Scans with a bounty** are never deleted by retention or by hand, because the bounty, votes and payouts depend on them.
- **Scans still being analysed** keep their file until they finish.
- **Each deletion run is logged:** for a team or a person, one `scan.expired` event records how many scans went (`via: system`).

## Deleting by hand

- **One scan:** `DELETE /submissions/{id}` (the Delete button on a report). Allowed for the person who made it, and for owners and admins of the team it's saved to. Not allowed for scans with a bounty. API keys need the `write` scope.
- **An account** (Profile → Settings) removes:
  - in user-service: the identity;
  - in the gateway: the copy of the account (renamed `deleted_<id>`), personal scans and their files, personal API keys, webhooks and their deliveries, and sessions. The person also leaves their teams, and a team they alone owned passes to its next admin;
  - in notification-service: preferences (email address, webhook) and history.

  Scans saved to teams stay with the teams. Audit entries stay until they expire, showing a deleted account.

## Export

`GET /users/me/export` (Profile → Data → Download) returns a JSON file with:
- the account;
- every scan the person made, with engine results;
- API keys (name, prefix, scopes; never the key);
- teams, webhooks (without their signing values), and up to 10,000 activity-log entries.

Uploaded files aren't included; their hashes are. API keys can't call it.

## Files

Uploads are stored on the gateway's upload volume (`UPLOAD_DIR`, shared with the analysis engine). The gateway deletes them directly. Anything that isn't a file under that folder is treated as a storage key: the gateway queues it on `artifact_deletions`, and the engine deletes it.

Before this, account deletion queued files under the wrong Redis key, and the engine passed local paths to the S3 client, so uploads of deleted accounts stayed on disk. To find files left over from that, list the upload folder on the server:

```bash
sudo docker exec verdyx-api-gateway sh -c 'ls /app/uploads'
```

Compare the list with `SELECT id FROM submissions WHERE file_path IS NOT NULL`, review it, and only then delete the files that no scan refers to. The first retention run also deletes every upload older than 30 days.

## Checking it

`scripts/test/retention-smoke.sh` checks deletion rights, settings, export and API-key rules through the API. The daily job needs time to pass, so it is checked by backdating rows in a throwaway database: `created_at` is set 40 or 100 days back, then the gateway is restarted with `RETENTION_FIRST_RUN_SECS=1`. Never do this on production.
