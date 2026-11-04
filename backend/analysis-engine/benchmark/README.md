# Detection benchmark

A fixed set of known-malicious and known-clean files, and a program that runs
every analysis engine over them. It answers two questions per engine:

- **How much malware does it flag?** (detection rate)
- **How many clean files does it wrongly flag?** (false-positive rate)

Every detection change (new YARA rules, ClamAV, a trained ML model, threshold
tuning) should be checked against it before it ships.

## What's in the set

| Part | Source | Size |
|---|---|---|
| Malicious | [MalwareBazaar](https://bazaar.abuse.ch), picked by `build_manifest.py` | 197 files, 87 families |
| Clean, Windows | Official releases of Python 3.12.7 (embeddable), MinGit 2.47.0, PuTTY 0.81, Notepad++ 8.7 | ~700 files |
| Clean, Linux | `/usr/bin` of the analysis-engine image (Debian trixie) | a few hundred files |

The malicious half covers Windows executables and DLLs (94), scripts (42:
PowerShell, JavaScript, VBScript, batch, HTA), Office documents (24), Linux ELF
(16), Android APK (9), LNK shortcuts (7) and PDF (5). Each family is capped at
4 samples (10 for Linux, where a few botnet families dominate) so one family
can't skew the result.

`manifest.json` holds the hashes, not the files. It is committed, so every run
measures the same samples.

## Running it

The samples are live malware. They are downloaded and analysed **on the
server**, inside containers, and never touch a workstation. They are only read
by the engines, never executed.

```bash
backend/analysis-engine/benchmark/run_on_server.sh ubuntu@<server> -i ~/.ssh/<key>
```

This:

1. uploads `manifest.json` and `fetch_samples.sh` to `/opt/verdyx-benchmark`;
2. downloads the samples in a throwaway Debian container (MalwareBazaar needs
   `ABUSE_CH_API_KEY`, read from the server's `.env`), checking every hash;
3. runs `verdyx-benchmark` from the live analysis-engine image, with no network
   and a 700 MB memory cap;
4. copies `report.md` and `report.json` back into `benchmark/results/`.

Samples stay on the server, so later runs only download what's missing.

## Reading the report

- **Flagged** means a Malicious or Suspicious verdict. **No verdict** means
  Unknown, an error, or the engine was unavailable.
- **Hash-reputation feeds are off.** The malicious set comes from
  MalwareBazaar, so a MalwareBazaar lookup would find every sample and make the
  score meaningless. The report measures what the engines see in the file
  itself. Use `--with-feeds` to include them anyway.
- The ML engine is advisory-only, so it never votes. Its prediction is scored
  separately as **ML Engine (advisory)**, which shows whether it has earned a
  vote.
- The **what it reacts to** tables list each engine's indicators by how often
  they fire on clean files versus malware. That is the data for tuning
  thresholds: drop or down-weight indicators that are common on both.
- `report.json` has every file's per-engine verdict, score and reasons, so
  threshold changes can be simulated without re-running the samples.

## Running it locally on clean files only

To check false positives without any malware, point the program at clean
files only (the malicious entries are skipped when absent):

```bash
cd backend/analysis-engine
cargo run --release --bin verdyx-benchmark --features yara-engine,ml-engine -- \
  --manifest benchmark/manifest.json --samples /path/to/samples \
  --clean-dir /usr/bin --rules /path/to/rules --out /tmp/bench
```

`/path/to/samples/clean/<name>/` can hold any clean software you unpack there.

## Refreshing the set

```bash
ABUSE_CH_API_KEY=... python3 build_manifest.py > manifest.json
```

Do this rarely and deliberately: a new set makes results incomparable with
earlier runs.
