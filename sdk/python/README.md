# verdyx (Python)

A Python SDK for [Verdyx](https://verdyx.dev) malware and URL scanning. Python 3.10 or later, standard library only.

## Install

The package isn't on PyPI yet. Until it is, install it from the repository:

```bash
pip install "git+https://github.com/deep60/Verdyx.git#subdirectory=sdk/python"
```

## Use

Create an API key on your profile page at verdyx.dev (**API keys** tab), with the `read` and `scan` scopes, and set `VERDYX_API_KEY`.

```python
from verdyx import Verdyx

client = Verdyx()  # reads VERDYX_API_KEY

result = client.scan("suspicious.exe")
print(result.verdict)     # "malicious" | "suspicious" | "clean" | "unknown"
print(result.votes)       # {"malicious": 3, "suspicious": 0, "clean": 1, "total": 4}
print(result.report_url)  # https://verdyx.dev/analysis/…
for e in result.engines:
    print(e.name, e.verdict, e.vote, e.reason)

if result.meets("suspicious"):
    raise SystemExit("blocked by Verdyx")
```

The steps separately:

```python
sub = client.submit_url("https://example.com/login", team_id="…")
result = client.wait_for_result(sub.id, timeout=120, on_status=print)
```

Files can also be bytes: `client.submit_file(data, filename="invoice.pdf")`.

Errors are `VerdyxError`, with `status` (the HTTP status), `body` and `retry_after`. A scan that doesn't finish in time raises `ScanTimeoutError`; the scan keeps running on the server. Reads are retried on network errors, 429 and 502–504, honouring `Retry-After`. Uploads aren't retried, so a lost response can't create a second scan.

| Argument | Default |
|---|---|
| `api_key` | `VERDYX_API_KEY` |
| `api_url` | `VERDYX_API_URL`, then `https://api.verdyx.dev` |
| `web_url` (for report links) | `VERDYX_WEB_URL`, then `https://verdyx.dev` |
| `timeout` (per request) | 60 s |
| `max_retries` | 3 |

## Tests

```bash
python -m unittest discover -s tests
```

The tests run against an in-process stand-in for the API.
