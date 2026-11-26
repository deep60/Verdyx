# Similarity search

Find files that are close to a scanned file, not just identical to it. A SHA-256 changes completely when one byte does, so a repacked or recompiled variant of known malware looks new. Fuzzy hashes don't.

Every uploaded file gets three hashes when it's scanned:

| Hash | What it measures |
|---|---|
| **TLSH** | A distance: 0 for the same content, rising as files differ. Under about 30 is very close; past 100, files are mostly unrelated. |
| **ssdeep** | A match score from 0 to 100. |
| **imphash** | For Windows programs, an MD5 of the import table, computed the same way as pefile. Programs built from the same code often share one. |

Files under 64 bytes, or too uniform to hash, get no TLSH or ssdeep. URL scans get none.

## Who sees what

Only uploads you could open yourself are searched: your own, your teams' (while you're a member), and scans posted with a bounty. A team API key searches only its team's uploads. Uploads made while signed out are never listed for anyone.

## `GET /api/v1/submissions/{id}/similar`

Needs a signed-in user or an API key with the `read` scope. The scan itself must be one you can open; otherwise the answer is 404.

```bash
curl -H "X-API-Key: $VERDYX_API_KEY" https://api.verdyx.dev/api/v1/submissions/<id>/similar
```

```json
{
  "submissionId": "…",
  "status": "ready",
  "hashes": { "tlsh": "T1…", "ssdeep": "768:…", "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744" },
  "compared": 1840,
  "similar": [
    {
      "submissionId": "…",
      "sha256": "…",
      "filename": "invoice_v2.exe",
      "fileSize": 245760,
      "createdAt": "2026-11-20T09:12:44Z",
      "verdict": "malicious",
      "reportUrl": "https://verdyx.dev/analysis/…",
      "match": { "closeness": "very_similar", "tlshDistance": 18, "ssdeepScore": 82, "sameImphash": true }
    }
  ]
}
```

- `status`: `ready`; `pending` while the scan is still running; `not_a_file` for a URL scan; `unavailable` when the file has no fuzzy hashes.
- `similar`: closest first, at most 25. `closeness` is `identical` (same SHA-256), `very_similar` (TLSH ≤ 30 or ssdeep ≥ 80), `similar` (TLSH ≤ 70 or ssdeep ≥ 55), `related` (TLSH ≤ 100 or ssdeep ≥ 40) or `same_imports` (only the imphash matches).
- `compared`: how many files were compared. These are the 5,000 most recent you can see, plus every file with the same imphash, whatever its age.

From the SDKs and CLI:

```bash
verdyx similar <scan-id>
```

```js
const r = await client.findSimilar(id);
```

```python
r = client.find_similar(scan_id)
```

The MCP server has the same thing as the `find_similar_files` tool.
