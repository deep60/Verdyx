# Verdyx scan (GitHub Action)

Scans build artifacts, downloaded files and URLs with [Verdyx](https://verdyx.dev) and fails the job on a malicious verdict. Each flagged file gets an annotation, and the job summary gets a table with links to the full reports.

```yaml
- uses: deep60/Verdyx/action@main
  with:
    api-key: ${{ secrets.VERDYX_API_KEY }}
    paths: |
      dist/**/*.exe
      dist/**/*.dll
    urls: https://downloads.example.com/latest
```

Pin it to a commit SHA rather than `@main` for anything that matters.

## Setup

1. Create an API key on your profile page at verdyx.dev (**API keys** tab), with the `read` and `scan` scopes.
2. Add it to the repository as a secret named `VERDYX_API_KEY` (**Settings → Secrets and variables → Actions**).

Without a key, scans are anonymous and more tightly rate limited. The runner needs Node.js 18 or later; GitHub-hosted runners have it.

## Inputs

| Input | Default | |
|---|---|---|
| `paths` | | Files, one per line. Globs work: `*`, `?`, `[abc]`, and `**` for any depth. Directories are skipped; use `dir/**` |
| `urls` | | URLs, one per line |
| `api-key` | | From a secret |
| `fail-on` | `malicious` | Fail when a verdict is at least `malicious`, `suspicious`, or `never` to only report |
| `timeout` | `300` | Seconds to wait for each scan |
| `team` | | Save the scans to this team (organization id) |
| `api-url` | `https://api.verdyx.dev` | |

## Outputs

| Output | |
|---|---|
| `verdict` | The worst verdict across all targets: `malicious`, `suspicious`, `clean` or `unknown` |
| `flagged` | How many targets reached `fail-on` |
| `results` | Path to a JSON file with every result |

## Examples

Report without failing, and act on the result yourself:

```yaml
- id: verdyx
  uses: deep60/Verdyx/action@main
  with:
    api-key: ${{ secrets.VERDYX_API_KEY }}
    paths: release/*.zip
    fail-on: never
- if: steps.verdyx.outputs.verdict != 'clean'
  env:
    VERDICT: ${{ steps.verdyx.outputs.verdict }}
  run: echo "Verdyx says $VERDICT; holding the release"
```

Check what a pull request adds to the repository:

```yaml
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: deep60/Verdyx/action@main
        with:
          api-key: ${{ secrets.VERDYX_API_KEY }}
          paths: |
            **/*.exe
            **/*.dll
            **/*.jar
```

Secrets aren't available to pull requests from forks, so those scans run anonymously.
