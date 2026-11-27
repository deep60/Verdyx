# Cloud storage scanning

Connect a bucket, and Verdyx scans the files that arrive in it: customer
uploads, files shared with partners, exports from other systems. It works
with any storage that speaks the S3 API:

- Amazon S3
- Cloudflare R2
- Google Cloud Storage (with HMAC keys)
- Backblaze B2, Wasabi, DigitalOcean Spaces, MinIO and other S3-compatible
  storage

Team owners and admins set it up on the team's **Storage** tab, at
[verdyx.dev/teams](https://verdyx.dev/teams). A team can connect up to five
buckets.

## How it works

- Verdyx looks for new files on a schedule you choose: every 15 minutes,
  hourly, every 3 or 6 hours, or daily. **Scan now** looks straight away.
- Each new or changed file is downloaded and scanned like an upload, with
  the analysis you choose (Quick, Full or Deep). A file is known by its key
  and ETag, so a file is scanned again only when it changes.
- Scans are saved to the team, in the name of the person who set up the
  connection, so the team's [webhooks](../api/webhooks.md),
  [Splunk](splunk.md) and [Sentinel](sentinel.md) destinations get each
  `analysis.completed` event. Each scan is named after the file's key.
- Files larger than the size limit you set (up to 100 MB) are listed as not
  scanned. Empty files and folder markers are skipped.
- By default only files added or changed after you connect are scanned.
  Turn on **Also scan the files already there** to scan the bucket's
  existing files too.
- Verdyx scans up to 25 files a minute per connection, so a large backlog
  takes a while. Use a **folder** (key prefix) to scan only part of a bucket.

The **Storage** tab shows when each bucket was last checked, how many files
were scanned and flagged, and the latest files with their verdicts.

Verdyx only lists and downloads. It never changes, moves or deletes files,
so a read-only key is enough, and is what you should give it.

## Amazon S3

1. In IAM, create a user (or role user) for Verdyx with this policy, using
   your bucket's name:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "s3:ListBucket",
         "Resource": "arn:aws:s3:::your-bucket"
       },
       {
         "Effect": "Allow",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::your-bucket/*"
       }
     ]
   }
   ```

   If the bucket is encrypted with a customer-managed KMS key, also allow
   `kms:Decrypt` on that key.
2. Create an access key for the user.
3. In Verdyx choose **Amazon S3**, and enter the bucket's region (such as
   `eu-west-2`), its name, and the access key ID and secret access key.

## Cloudflare R2

1. In the Cloudflare dashboard, go to **R2 → Manage R2 API Tokens → Create
   API token**. Choose **Object Read only**, and apply it to this bucket.
2. Copy the **Access Key ID**, the **Secret Access Key**, and the
   S3 endpoint for your account: `https://<account id>.r2.cloudflarestorage.com`.
3. In Verdyx choose **Cloudflare R2**, and enter the endpoint, the bucket's
   name and the key.

## Google Cloud Storage

1. Create a service account, and give it **Storage Object Viewer** on the
   bucket.
2. In **Cloud Storage → Settings → Interoperability**, create an **HMAC
   key** for that service account.
3. In Verdyx choose **Google Cloud Storage**, and enter the bucket's name and
   the HMAC key's access ID and secret.

## Other S3-compatible storage

Choose **Other S3-compatible**, and enter the provider's S3 endpoint (for
example `https://s3.eu-central-003.backblazeb2.com` for Backblaze B2, or
`https://s3.wasabisys.com` for Wasabi), the bucket's region, its name and a
read-only key.

The endpoint must use https and be reachable from the internet: Verdyx
doesn't connect to private or internal addresses. A MinIO server on your own
network needs a public address and certificate.

## API

These need an owner's or admin's session or personal API key. Team API keys
can't use them.

| Request | What it does |
|---|---|
| `GET /api/v1/orgs/{id}/storage` | The team's connections, with their status and counts |
| `POST /api/v1/orgs/{id}/storage` | Connect a bucket (see below). It's tested first |
| `PATCH /api/v1/orgs/{id}/storage/{connection}` | Change any field; send `enabled: false` to pause |
| `DELETE /api/v1/orgs/{id}/storage/{connection}` | Disconnect. The scans already made stay with the team |
| `POST /api/v1/orgs/{id}/storage/{connection}/scan` | Look for new files now |
| `GET /api/v1/orgs/{id}/storage/{connection}/objects` | The latest files and their verdicts; `?flagged=true` for flagged ones only |

```json
{
  "name": "Customer uploads",
  "provider": "aws",
  "region": "eu-west-2",
  "bucket": "acme-uploads",
  "prefix": "incoming/",
  "accessKeyId": "AKIA…",
  "secretAccessKey": "…",
  "analysisType": "full",
  "intervalMinutes": 60,
  "maxObjectMb": 32,
  "scanExisting": false
}
```

`provider` is `aws`, `r2`, `gcs` or `other`. `endpoint` is required for `r2`
and `other`. `intervalMinutes` is 15, 60, 180, 360 or 1440. When you change
the location or the access key ID, send the secret access key too; the
connection is tested again.

Every change is written to the team's activity log: buckets connected,
changed and disconnected, and scans asked for.

## How it's kept safe

- The secret access key is stored encrypted and never shown again.
- Requests are signed with AWS Signature Version 4, and go only to public
  addresses over https, without following redirects.
- Each connection is tested when it's saved, so a wrong key or bucket is
  found straight away.
- Team owners and admins manage connections; team API keys can't.

## If it doesn't work

The **Storage** tab shows why the last check failed:

| Message | What to check |
|---|---|
| the secret access key is wrong | Copy the secret again; it's shown only once by your provider |
| the access key ID is wrong or was deleted | The key exists and is active |
| the key isn't allowed to list or read this bucket | The policy allows listing the bucket and reading its objects (and `kms:Decrypt`, for KMS-encrypted buckets) |
| there's no bucket by that name | The bucket's name, and for other providers the endpoint |
| the bucket is in a different region | The region, for Amazon S3 |
| couldn't reach the storage service | The endpoint, and that it's reachable from the internet |

A file that couldn't be downloaded is shown with the reason, and is tried
again the next day.
