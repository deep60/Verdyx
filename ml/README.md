# Verdyx ML

Trained models for the analysis engine, and the small service that runs them.

Stage 1, here now: **a Windows-program (PE) model**. It's LightGBM trained on
[EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) with EMBER's own
feature extractor, and it has:

- **Realistic testing.** Training uses older files and testing uses newer
  ones. No random split anywhere.
- **Fixed false-positive thresholds.** "Malicious" is set at 0.1% false
  positives and "suspicious" at 1%. Both are chosen on held-out weeks, then
  reported on later weeks.
- **Calibrated scores.** Isotonic regression makes 0.9 mean "about 90% of
  files like this were malicious", so the engine's confidence averages fairly
  with the others.
- **Explanations.** Exact SHAP values (LightGBM's built-in TreeSHAP) name the
  imports, sections, strings and header fields that pushed the score. One
  example: `imported function: kernel32.dll:virtualallocex`.
- **A quality gate.** A model that misses the bar is still installed, but it's
  advisory: it's shown on results and doesn't vote.

```
 analysis-engine (Rust)  ──POST file bytes──▶  ml-service (Python, this dir)
   pe_model_analyzer.rs   ◀── verdict, calibrated probability, SHAP reasons ──
```

The model runs in Python because EMBER2024's features come from Python's
`pefile` and `signify`. That includes `pefile`'s own parser warnings, which no
Rust re-implementation could match exactly. Training and serving share
`verdyx_ml/pe_features.py`, so the model always sees features computed by the
same code.

## Train the model (on your Mac or a Linux machine)

You need:

- **Disk:** about 80 GB free. That's the downloaded data (Win32, Win64 and
  .NET are about 30 GB) plus the vectorized cache (about 30 GB).
- **RAM:** 32 GB for the full training set. With 16 GB, use
  `--train-sample 0.5`.
- **Time:** about 1–2 hours to vectorize and a few hours to train, depending
  on cores.
- **Python:** 3.11. On macOS, also run `brew install libomp`, which LightGBM
  needs.

```bash
cd ml
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
python -m verdyx_ml.train_pe --data-dir ~/ember2024 --out-dir ./bundle --download
```

`--download` fetches the data the first time; drop it on later runs. The
vectorized features are cached in `~/ember2024/verdyx_cache`, so retraining
with different settings skips the slow part.

The output goes to `./bundle`:

| File | What it is |
|---|---|
| `model.txt` | LightGBM model, tens of MB |
| `calibration.json` | Raw score → probability mapping |
| `bundle.json` | Thresholds, every evaluation number, the gate result, training settings |
| `report.md` | The evaluation in plain words. **Read this before deploying.** |

The command exits with status 0 if the model passed the quality gate and 2 if
it didn't. The default gate, measured on the test weeks, is: AUC ≥ 0.97,
detection ≥ 70% at the malicious threshold, false positives ≤ 0.3% at the
malicious threshold, and calibration error ≤ 0.05. To change a limit, pass it,
for example `--min-test-tpr-at-malicious-threshold 0.8`.

The report includes:

- the four time slices (fit / valid / calib / test) with their date ranges
- detection and false-positive rates at both thresholds on the test weeks
- detection at 0.1% FPR **if tuned on the test data itself**. That's the number
  papers usually quote; it appears only for comparison
- the challenge set: evasive malware that EMBER2024 holds out
- a calibration table, month-by-month drift, per file type, and the biggest
  malware families

## Deploy it

The service runs on the **worker**, an Always Free Ampere A1 VM next to the main
1 GB VM, together with ClamAV. Its setup, from creating the VM to pointing the
engine at it, is in [`deploy/worker/README.md`](../deploy/worker/README.md).

The engine status page now lists **Windows Program Model (EMBER2024)**, and
every scanned `.exe` or `.dll` gets a detection with a `summary`
("Main reasons: …") and full `explanation` metadata. Non-PE files are never
sent to the service.

To update the model, replace the bundle files in
`/opt/verdyx-worker/ml-models/pe` on the worker and run
`sudo docker restart verdyx-ml-service`. The image itself is rebuilt by CI and kept
up to date by Watchtower.

Settings on the engine side, in `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `PE_MODEL_URL` | unset (off) | ML service address |
| `PE_MODEL_VOTE` | `auto` | `auto`: vote only if the gate passed. `always` / `never` |
| `ML_SERVICE_TOKEN` | unset | Shared secret, sent as `X-Verdyx-ML-Token` |
| `PE_MODEL_TIMEOUT_SECS` | 20 | Per-file timeout |

## Develop

```bash
cd ml && pip install -r requirements-dev.txt && python -m pytest -q tests
```

The tests build real (harmless, one-instruction) Windows executables, run the
real EMBER extractor on them, and then exercise the whole path on miniature
EMBER-format data: train → split by time → calibrate → gate → bundle → HTTP
scoring with SHAP. On macOS, if LightGBM can't find `libomp`, either
`brew install libomp` or point it at scikit-learn's bundled copy:
`DYLD_LIBRARY_PATH=$(python -c 'import sklearn,os;print(os.path.join(os.path.dirname(sklearn.__file__),".dylibs"))')`.

## Pinned versions, and why

Everything in `requirements.txt` is exact, because the model is only as good as
the match between training features and production features. EMBER2024
(`thrember`) is pinned to a commit. `signify` is held at 0.9.3: every version
below 0.9.2 has a high-severity advisory in the authenticode parser this service
runs on untrusted uploads. thrember was written for 0.7's API, so
`pe_features.py` adapts 0.9's to it. On 229 real Windows programs (120 signed)
the features are identical to 0.7.1's, value for value.

## Roadmap

| Stage | What | Status |
|---|---|---|
| 1 | PE model: LightGBM on EMBER2024, time-split testing, calibration, SHAP, quality gate | **done** (needs your training run) |
| 2 | Byte-level deep model (MalConv2) on SOREL-20M/BODMAS for packed and new malware | next; needs a GPU to train and more RAM than the 1 GB box to serve |
| 3 | URL and phishing: character-level URL model, plus screenshot similarity to known login pages | planned |
| — | Family labels: EMBER2024 already has a family per sample (it's in the report) | planned, after stage 2 |
| — | Analyst feedback: settled disputes become training labels | planned |
