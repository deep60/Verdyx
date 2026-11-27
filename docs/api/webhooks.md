# Webhooks

Verdyx sends an HTTP `POST` to your URL when something happens to your scans: a scan finishes, its verdict changes, or one of your live hunts matches a new upload. Use webhooks to feed a SIEM, a chat channel or your own automation.

## Set one up

On your profile page, open the **API and webhooks** tab. Or use the API:

```http
POST /api/v1/webhooks
{ "url": "https://hooks.example.com/verdyx", "events": ["analysis.completed", "livehunt.match"] }
```

The response includes `secret` (`whsec_…`). Keep it somewhere safe; it's how you check that a delivery really came from Verdyx.

| Field | |
|---|---|
| `url` | `https://` or `http://`, on the public internet. Private, loopback, link-local and cloud-metadata addresses are refused. That covers IP addresses written in any notation, and names that resolve to such addresses, which are checked again each time a delivery connects. Credentials in the URL aren't allowed; use `headers` |
| `events` | One or more of the events below, or `"*"` for all. At most 20 |
| `headers` | Optional extra headers, for example `{"Authorization": "Bearer …"}`. String values only, at most 10. `Host`, `Content-Type`, `Content-Length`, `User-Agent` and `X-Verdyx-*` can't be set |

The **Test** button, or `POST /api/v1/webhooks/{id}/test {"event_type": "webhook.test"}`, sends a signed test delivery straight away and returns what your endpoint answered.

## Splunk and Microsoft Sentinel

A webhook can send straight into a SIEM instead of to your own URL. Set `kind`:

| `kind` | Sends to | Needs |
|---|---|---|
| `webhook` | Your URL, signed (the default) | `url` |
| `splunk` | Splunk's HTTP Event Collector, one Splunk event per Verdyx event | `url` (the HEC address), `credential` (the HEC token); optional `config.index`, `config.sourcetype` |
| `sentinel` | A Sentinel custom table through the Logs Ingestion API | `url` (the data collection endpoint), `credential` (the Entra app's client secret), `config.tenantId`, `config.clientId`, `config.dcrImmutableId`; optional `config.streamName` |

`credential` is stored encrypted and never returned: responses carry
`has_credential` instead. To replace it, send a new one with
`PUT /api/v1/webhooks/{id}`. Events, retries and the delivery log are the
same as for webhooks. Setup guides: [Splunk](../integrations/splunk.md),
[Microsoft Sentinel](../integrations/sentinel.md).

## Events

| Event | When | `data` |
|---|---|---|
| `analysis.completed` | A scan you submitted finished | `submissionId`, `status`, `type` (`file`, `url` or `email`), `target` (file name or URL), `sha256`, `isMalicious`, `confidence`, `engineResults` (how many engine results), `teamId`, `reportUrl` |
| `analysis.updated` | A finished scan's verdict changed, for example when a sandbox report arrives later | The same as `analysis.completed` |
| `livehunt.match` | One of your live hunts matched a new upload | `huntId`, `huntName`, `teamId`, `submissionId`, `rules` (the rule names that matched), `target`, `sha256`, `reportUrl` |
| `webhook.test` | Only from the Test button | What the test request sent |

Events go to the person who caused them: the uploader for `analysis.*`, the hunt's owner for `livehunt.match`. Anonymous scans send nothing. For the full engine-by-engine result, call `GET /api/v1/submissions/{submissionId}/consensus` and `/analyses` with an API key.

## What a delivery looks like

```http
POST /verdyx HTTP/1.1
Content-Type: application/json
User-Agent: Verdyx-Webhooks/1.0 (+https://verdyx.dev)
X-Verdyx-Event: analysis.completed
X-Verdyx-Delivery: 5b0c8f1e-…
X-Verdyx-Timestamp: 1764072000
X-Verdyx-Signature: t=1764072000,v1=3f9a…

{
  "id": "5b0c8f1e-…",
  "event": "analysis.completed",
  "createdAt": "2026-11-25T12:00:00Z",
  "data": {
    "submissionId": "9d2e…",
    "type": "file",
    "target": "invoice.exe",
    "sha256": "e3b0…",
    "isMalicious": true,
    "confidence": 0.75,
    "engineResults": 9,
    "teamId": null,
    "status": "completed",
    "reportUrl": "https://verdyx.dev/analysis/9d2e…"
  }
}
```

- **Delivery id:** `id`, which is also in `X-Verdyx-Delivery`, is the same on every retry of a delivery. Use it to ignore duplicates.
- **Order:** deliveries may arrive out of order. Use `createdAt` if order matters.

## Checking the signature

`X-Verdyx-Signature` is `t=<unix seconds>,v1=<hex>`, where `<hex>` is the HMAC-SHA256 of `<t>.<raw body>` keyed with your webhook's secret. To check it:
1. Compute the HMAC over the **raw** request body, before any JSON parsing.
2. Compare it in constant time.
3. Reject timestamps more than 5 minutes old, so a captured delivery can't be replayed.

**Node.js:**

```js
import crypto from "node:crypto";

function verify(rawBody, header, secret, toleranceSeconds = 300) {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")));
  const t = Number(parts.t);
  if (!t || Math.abs(Date.now() / 1000 - t) > toleranceSeconds) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex");
  const given = Buffer.from(parts.v1 ?? "", "hex");
  const want = Buffer.from(expected, "hex");
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}
```

**Python:**

```python
import hashlib, hmac, time

def verify(raw_body: bytes, header: str, secret: str, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts.get("t", "0"))
    if abs(time.time() - t) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
```

## Retries

- **Success:** any `2xx` answer within 10 seconds. Anything else is retried, including redirects, which aren't followed.
- **Attempts:** up to the webhook's `retry_max_attempts`, 3 by default, at most 10.
- **Wait between attempts:** starts at `retry_interval_seconds` (60 by default) and doubles each time (`exponential_backoff`), up to 6 hours.
- **Turned-off webhooks:** deliveries to a turned-off webhook fail without being sent.
- **Delivery log:** `GET /api/v1/webhooks/{id}/deliveries` shows each delivery with its status (`pending`, `sending`, `retrying`, `success` or `failed`), the HTTP status, the first 1,000 characters of your response, and the error. Finished deliveries are kept for 30 days.

Answer quickly and do the work afterwards. A slow endpoint times out and gets the same delivery again.
