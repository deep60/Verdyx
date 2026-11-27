# Email scanning

Verdyx scans an email the way it scans an archive:

- **Attachments**: each one is scanned by every engine, as if it had been
  uploaded on its own. A zip inside an email is opened too, including zips
  locked with the usual sample passwords (`infected`, `malware`, `virus`).
  A forwarded message is opened, and its attachments are scanned in turn.
  Images shown inline in the text (logos, signatures) are skipped.
- **Links**: up to five links from the text and HTML are looked up in
  URLhaus, ThreatFox and Verdyx's own URL checks, plus Google Safe Browsing
  and VirusTotal when they're set up. Links to unfamiliar sites are looked up
  before links to well-known ones, one per site. The pages themselves aren't
  opened.
- **Headers**: SPF, DKIM and DMARC results, forged or suspicious headers,
  the route through mail servers, and urgency or credential-phishing
  wording.

The report lists each attachment and link with its verdict. An attachment
judged malicious makes the email malicious. A link on a blocklist makes it at
least suspicious, but doesn't decide the verdict alone, since emails
sometimes quote a bad link to warn people about it.

Quick analysis doesn't open attachments. Full and Deep do (Deep goes one
level further into archives inside archives). An email can carry up to 25
attachments of up to 24 MB each, 48 MB in all (50 attachments with Deep);
any beyond that are listed as not scanned.

## Scanning an email

**On the website:** on the [dashboard](https://verdyx.dev/dashboard), choose **Email**, then paste the
message source or upload a `.eml` file. In Outlook, open the message and
choose **File → Save As** (or drag it to the desktop); in Gmail, choose
**⋮ → Download message**.

**With the API:** send the raw message as the body:

```bash
curl -s https://api.verdyx.dev/api/v1/submissions/email \
  -H "X-API-Key: $VERDYX_API_KEY" \
  -H "Content-Type: message/rfc822" \
  --data-binary @message.eml
```

Optional query parameters:

| Parameter | |
|---|---|
| `organizationId` | Save the scan to a team (a team key always saves to its team) |
| `analysisType` | `quick`, `full` (the default), `deep` or `behavioral` |
| `description` | A note shown on the scan |

The answer is the scan, with its `id`; follow it as for any other scan
(`GET /submissions/{id}`). The scan is named after the email's subject.
Emails up to 40 MB are accepted. Uploading a `.eml` file to
`POST /submissions/file` works too.

## A phishing-report mailbox

Give your people an address such as `phishing@example.com` to forward
suspicious emails to, and scan everything that arrives. Ask them to forward
**as an attachment** (Outlook: **More → Forward as attachment**; Gmail:
select the message, then **⋮ → Forward as attachment**), so the original
headers, attachments and links are kept. Verdyx opens the forwarded message
and scans what's inside it.

With [Cloudflare Email Routing](https://developers.cloudflare.com/email-routing/),
an Email Worker hands each message to Verdyx. Make a team API key with the
**scan** scope, store it as the Worker's secret `VERDYX_API_KEY`, and route
the address to this Worker:

```js
export default {
  async email(message, env) {
    const res = await fetch("https://api.verdyx.dev/api/v1/submissions/email", {
      method: "POST",
      headers: {
        "Content-Type": "message/rfc822",
        "X-API-Key": env.VERDYX_API_KEY,
      },
      body: await new Response(message.raw).arrayBuffer(),
    });
    if (!res.ok) {
      message.setReject(`Verdyx couldn't take the message (${res.status})`);
    }
  },
};
```

The scans are saved to the team that owns the key. To hear about the bad
ones, add a [webhook](../api/webhooks.md) for `analysis.completed`, or send
the team's events to [Splunk](splunk.md) or [Sentinel](sentinel.md).

Any mail system that can run a script or call a URL per message (a Microsoft
365 or Google Workspace add-on, a Postfix pipe, an n8n or Zapier flow) can do
the same: send the raw message to `POST /submissions/email`.
