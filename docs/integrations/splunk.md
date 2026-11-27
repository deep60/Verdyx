# Splunk

Verdyx sends events to Splunk through the **HTTP Event Collector (HEC)**: one
Splunk event per Verdyx event, as they happen, retried if Splunk is down.

## 1. In Splunk: create a HEC token

1. **Settings → Data inputs → HTTP Event Collector → New Token.**
2. Name it `verdyx`. Leave *Enable indexer acknowledgement* off.
3. Source type: choose **New** and enter `verdyx:event` (or pick your own).
4. Choose the index, for example a `security` index, and finish.
5. Copy the token value.

Check **Global Settings** on the HEC page: HEC must be enabled, and SSL on.

The HEC address is:

| Splunk | URL |
|---|---|
| Splunk Enterprise | `https://<your-server>:8088` |
| Splunk Cloud Platform | `https://http-inputs-<stack>.splunkcloud.com` |

The address must be reachable from the internet and use a certificate from a
public authority. Verdyx checks the certificate, so a self-signed one fails.

## 2. In Verdyx: add the destination

On your profile page, open the **Webhooks** tab and choose **Splunk**, then fill in:

- **HEC URL**: the address above. `/services/collector/event` is added for you.
- **HEC token**: the token from step 1. It's stored encrypted and never shown
  again. To change it, delete the destination and add it again, or send a new one
  with `PUT /api/v1/webhooks/{id}`.
- **Index** (optional): leave empty to use the token's default index.
- **Sourcetype** (optional): `verdyx:event` by default.
- **Events**: which events to send.

Press **Test** on the new destination. A green result with HTTP 200 means
Splunk accepted the event.

Or with the API:

```bash
curl -X POST https://api.verdyx.dev/api/v1/webhooks \
  -H "X-API-Key: $VERDYX_API_KEY" -H "Content-Type: application/json" \
  -d '{"kind":"splunk","url":"https://splunk.example.com:8088","credential":"<HEC token>",
       "config":{"index":"security"},"events":["analysis.completed","livehunt.match"]}'
```

## 3. Search the events

Each Splunk event holds the same envelope a webhook gets
([event reference](../api/webhooks.md)):

```
index=security sourcetype="verdyx:event" event="analysis.completed" data.isMalicious=true
| table _time data.target data.sha256 data.confidence data.reportUrl
```

Live-hunt matches:

```
index=security sourcetype="verdyx:event" event="livehunt.match"
| stats count by data.huntName, data.rules{}
```

## If it doesn't arrive

The destination's **Delivery logs** say what Splunk answered:

| Result | Meaning |
|---|---|
| HTTP 403: Splunk refused the HEC token | The token is wrong or disabled. |
| HTTP 400: check the index is allowed | The index isn't one the token may write to. |
| could not connect | The address isn't reachable from the internet, or the port is closed. |
| request failed: invalid certificate | The HEC certificate isn't from a public authority. |

Failed deliveries are retried with backoff, 3 attempts by default.
