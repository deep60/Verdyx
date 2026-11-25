# verdyx (JavaScript/TypeScript)

The `verdyx` command and a JavaScript/TypeScript SDK for [Verdyx](https://verdyx.dev) malware and URL scanning. Node.js 18 or later, no dependencies.

## Install

The package isn't on npm yet. Until it is, run it from a clone of the repository:

```bash
git clone https://github.com/deep60/Verdyx.git
```

```bash
cd Verdyx/sdk/typescript && npm link
```

## API key

Create a key on your profile page at verdyx.dev (**API keys** tab), with the `read` and `scan` scopes. Then set it in your environment:

```bash
export VERDYX_API_KEY=vdx_...
```

Without a key, scans are anonymous and more tightly rate limited. The CLI reads the key only from the environment, never from an argument, so it doesn't end up in shell history or process lists.

## The command

```bash
verdyx scan suspicious.exe https://example.com/login
```

```text
MALICIOUS  suspicious.exe             3/4 voting engines flagged it  https://verdyx.dev/analysis/…
CLEAN      https://example.com/login  0/3 voting engines flagged it  https://verdyx.dev/analysis/…
```

| Command | What it does |
|---|---|
| `verdyx scan <file-or-url>...` | Submit, wait, print the verdicts |
| `verdyx result <scan-id>...` | Show the result of earlier scans |
| `verdyx engines` | List the engines and whether each is online |

| Option | |
|---|---|
| `--json` | Print JSON instead of a table |
| `-v`, `--verbose` | Also show each engine's result |
| `--fail-on <level>` | Exit with code 2 when a verdict is at least `malicious` (default), `suspicious`, or `never` |
| `--timeout <seconds>` | Stop waiting after this long (default 300). The scan keeps running; fetch it later with `verdyx result` |
| `--no-wait` | Submit and print the scan ids |
| `--output <file>` | Also write the JSON results to a file |
| `--summary <file>` | Append a Markdown table (for `$GITHUB_STEP_SUMMARY`) |
| `--team <id>` | Save the scans to a team |

Exit codes: `0` everything is fine, `1` an error, a failed scan or a timeout, `2` a verdict reached `--fail-on`. That makes it usable as a gate in any CI system:

```bash
verdyx scan --fail-on suspicious dist/*.exe || exit 1
```

## The SDK

```js
import { Verdyx } from "verdyx";

const client = new Verdyx(); // reads VERDYX_API_KEY

const result = await client.scan("suspicious.exe");
console.log(result.verdict);   // "malicious" | "suspicious" | "clean" | "unknown"
console.log(result.votes);     // { malicious: 3, suspicious: 0, clean: 1, total: 4 }
console.log(result.reportUrl); // https://verdyx.dev/analysis/…
for (const e of result.engines) console.log(e.name, e.verdict, e.vote, e.reason);
```

The steps separately:

```js
const sub = await client.submitUrl("https://example.com/login", { teamId: "…" });
const result = await client.waitForResult(sub.id, { timeoutSeconds: 120, onStatus: console.log });
```

Files can also be bytes: `client.submitFile(buffer, { filename: "invoice.pdf" })`.

Errors are `VerdyxError`, with `status` (the HTTP status) and `body`. A scan that doesn't finish in time throws `ScanTimeoutError`; the scan keeps running on the server. Reads are retried on network errors, 429 and 502–504, honouring `Retry-After`. Uploads aren't retried, so a lost response can't create a second scan.

| Option | Default |
|---|---|
| `apiKey` | `VERDYX_API_KEY` |
| `apiUrl` | `VERDYX_API_URL`, then `https://api.verdyx.dev` |
| `webUrl` (for report links) | `VERDYX_WEB_URL`, then `https://verdyx.dev` |
| `maxRetries` | 3 |
| `fetch` | the global `fetch` |

## Tests

```bash
node --test test/*.test.js
```

The tests run against `test/mock-server.js`, a stand-in for the API that never touches production.
