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
| Clean, scripts | Pester 5.6.1 and PSScriptAnalyzer 1.23.0 (PowerShell), jQuery 3.7.1 and Bootstrap 5.3.3 (JavaScript) | ~1,200 files |
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
3. runs `verdyx-benchmark` from the live analysis-engine image with a 700 MB
   memory cap. ClamAV and the Windows program model (EMBER2024) run on the
   worker VM: each is used when production has it set up (`CLAMAV_HOST`,
   `PE_MODEL_URL`) and it answers, and the run then gets a network to reach
   them. Otherwise it has none. `BENCHMARK_CLAMAV=off` and
   `BENCHMARK_PE_MODEL=off` leave them out;
4. copies `report.md`, `report.json` and `run.json` back into `benchmark/results/`.

Samples stay on the server, so later runs only download what's missing.

## Publishing the results

The public page at [verdyx.dev/benchmark](https://verdyx.dev/benchmark) shows
the latest run. After `run_on_server.sh`, regenerate its data and commit it
with the change that moved the numbers:

```bash
python3 backend/analysis-engine/benchmark/publish.py
```

This reads `results/report.json` and `results/run.json` (when the run
happened, and the engine image's digest and git commit) and writes
`frontend/client/src/data/benchmark.json`. Only totals and the names of
flagged clean files are published, nothing about individual malware samples.
Tests: `python3 -m unittest backend/analysis-engine/benchmark/test_publish.py`.

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

## Seeing why scripts are missed

```bash
backend/analysis-engine/benchmark/describe_on_server.sh ubuntu@<server> -i ~/.ssh/<key> > script-profiles.txt
```

This prints a text profile of each malicious script: its encoding, line
lengths, character mix, most common words, counts of obfuscation markers, and
short excerpts. It runs on the server in a container with no network and the
samples mounted read-only, so only the text comes back. `DESCRIBE_ONLY="<sha
prefix> ..."` limits it to some samples. The script detections in
`src/analyzers/script_layers.rs` were written from these profiles.

To check a detection change for false positives on clean scripts you have
locally (for example a `node_modules` folder):

```bash
SCRIPT_CORPUS=/path/to/scripts cargo test -p analysis-engine --lib clean_corpus -- --ignored --nocapture
```

It lists every file the heuristic engine flags with script unwrapping that it
didn't flag without.

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
