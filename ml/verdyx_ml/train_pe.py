"""Train, calibrate and evaluate the Windows-program (PE) model on EMBER2024.

Run from the `ml/` directory:

    python -m verdyx_ml.train_pe --data-dir ~/ember2024 --out-dir ./bundle --download

Steps:
  1. (optional) download EMBER2024's PE files: Win32, Win64 and .NET.
  2. Vectorize them with EMBER2024's own extractor, sorted oldest first.
  3. Split by time. EMBER's train weeks are cut three ways:
         fit   oldest ~80%   trains the trees
         valid next ~8%     picks the number of trees (early stopping)
         calib newest ~12%  fits calibration and sets the thresholds
     EMBER's test weeks (later still) are touched only for the final report,
     so the numbers show how the model does on malware newer than anything
     it learned from. No random split anywhere.
  4. Train LightGBM, calibrate with isotonic regression, set the
     malicious/suspicious thresholds at fixed false-positive rates.
  5. Report on the test weeks and the challenge set (evasive malware), apply
     the quality gate, and write the bundle the ML service loads.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from . import __version__, dataset, metrics
from .bundle import (
    CALIBRATION_FILE,
    MODEL_FILE,
    REPORT_FILE,
    write_meta,
)
from .calibration import fit_isotonic
from .pe_features import CATEGORICAL_FEATURES

DEFAULT_PARAMS = {
    "objective": "binary",
    "metric": "binary_logloss",
    "learning_rate": 0.05,
    # 128 leaves x up to ~1500 trees stays small (tens of MB), which matters
    # on a 1 GB server. EMBER's benchmark grid goes to 2048 leaves.
    "num_leaves": 128,
    "min_data_in_leaf": 200,
    "feature_fraction": 0.5,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "max_bin": 255,
    "seed": 7,
    "deterministic": True,
    "verbose": -1,
}

THRESHOLDS_FPR = {"malicious": 0.001, "suspicious": 0.01}

# Defaults are deliberately conservative. A model that fails them is still
# written, but the analysis engine treats it as advisory: it is shown and
# does not vote.
DEFAULT_GATE = {
    "min_test_auc": 0.97,
    "min_test_tpr_at_malicious_threshold": 0.70,
    "max_test_fpr_at_malicious_threshold": 0.003,
    "max_test_ece": 0.05,
}


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def download(data_dir: Path) -> None:
    import thrember  # full package: only needed for the download helper

    data_dir.mkdir(parents=True, exist_ok=True)
    cwd = os.getcwd()  # download_dataset changes directory
    try:
        for split in ("train", "test"):
            _log(f"downloading EMBER2024 PE {split} files into {data_dir}")
            thrember.download_dataset(str(data_dir), split=split, file_type="PE")
        _log("downloading the challenge set")
        thrember.download_dataset(str(data_dir), split="challenge", file_type="all")
    finally:
        os.chdir(cwd)


def time_split(n: int, valid_frac: float, calib_frac: float) -> tuple[int, int]:
    """End indices of fit and valid in a time-sorted array."""
    n_calib = max(1, int(round(n * calib_frac)))
    n_valid = max(1, int(round(n * valid_frac)))
    fit_end = n - n_calib - n_valid
    if fit_end < 1:
        raise ValueError(f"only {n} training rows: too few to split by time")
    return fit_end, fit_end + n_valid


def _period_breakdown(split: dataset.Split, score: np.ndarray, threshold: float) -> list[dict]:
    """Detection and false-positive rate per calendar month, to see drift."""
    months = np.array([_iso(d)[:7] for d in split.date])
    rows = []
    for m in sorted(set(months)):
        mask = months == m
        r = metrics.rates_at(split.y[mask], score[mask], threshold)
        rows.append({"period": m, **{k: r[k] for k in ("tpr", "fpr", "malicious", "benign")}})
    return rows


def _by_type(split: dataset.Split, score: np.ndarray, threshold: float) -> list[dict]:
    rows = []
    for t in sorted(set(split.file_type.tolist())):
        mask = split.file_type == t
        r = metrics.rates_at(split.y[mask], score[mask], threshold)
        rows.append({"file_type": t or "unknown", **{k: r[k] for k in ("tpr", "fpr", "malicious", "benign")}})
    return rows


def _families(split: dataset.Split, score: np.ndarray, threshold: float, top: int = 15) -> list[dict]:
    mal = split.y == 1
    fams, counts = np.unique(split.family[mal & (split.family != "")], return_counts=True)
    rows = []
    for f in fams[np.argsort(-counts)][:top]:
        m = mal & (split.family == f)
        rows.append({"family": str(f), "count": int(m.sum()), "detected": float((score[m] >= threshold).mean())})
    return rows


def predict(booster, X: np.ndarray, chunk: int = 100_000) -> np.ndarray:
    """Raw scores, a chunk at a time so a large memmap is never copied whole."""
    if len(X) == 0:
        return np.zeros(0)
    return np.concatenate([booster.predict(X[s : s + chunk]) for s in range(0, len(X), chunk)])


def evaluate(booster, calib, thresholds: dict, split: dataset.Split) -> dict:
    raw = predict(booster, split.X)
    prob = calib(raw)
    out = {
        "rows": len(split),
        "malicious": int(split.y.sum()),
        "benign": int((split.y == 0).sum()),
        "date_range": [_iso(split.date.min()), _iso(split.date.max())] if len(split) else None,
    }
    if out["malicious"] and out["benign"]:
        out["auc"] = metrics.roc_auc(split.y, raw)
        out["ece"] = metrics.expected_calibration_error(split.y, prob)
        out["brier"] = metrics.brier(split.y, prob)
        out["reliability"] = metrics.reliability(split.y, prob)
        # For comparison with published numbers only: a threshold tuned on
        # the test data itself, which a deployed model never gets to do.
        out["oracle_tpr_at_0.1pct_fpr"] = metrics.rates_at(
            split.y, raw, metrics.threshold_at_fpr(split.y, raw, 0.001)
        )["tpr"]
    for name, t in thresholds.items():
        out[f"at_{name}_threshold"] = metrics.rates_at(split.y, raw, t)
    if out["malicious"] and out["benign"]:
        out["by_month"] = _period_breakdown(split, raw, thresholds["malicious"])
        out["by_file_type"] = _by_type(split, raw, thresholds["malicious"])
    out["families"] = _families(split, raw, thresholds["malicious"])
    return out


def quality_gate(test: dict, gate: dict) -> dict:
    checks = []

    def check(name, value, ok):
        checks.append({"check": name, "value": value, "passed": bool(ok)})

    m = test.get("at_malicious_threshold", {})
    auc, ece = test.get("auc"), test.get("ece")
    check(f"test AUC >= {gate['min_test_auc']}", auc, auc is not None and auc >= gate["min_test_auc"])
    check(
        f"test detection rate at the malicious threshold >= {gate['min_test_tpr_at_malicious_threshold']}",
        m.get("tpr"), m.get("tpr", 0) >= gate["min_test_tpr_at_malicious_threshold"],
    )
    check(
        f"test false-positive rate at the malicious threshold <= {gate['max_test_fpr_at_malicious_threshold']}",
        m.get("fpr"), m.get("fpr", 1) <= gate["max_test_fpr_at_malicious_threshold"],
    )
    check(f"test calibration error (ECE) <= {gate['max_test_ece']}", ece, ece is not None and ece <= gate["max_test_ece"])
    return {"passed": all(c["passed"] for c in checks), "checks": checks, "limits": gate}


def _pct(v) -> str:
    return "n/a" if v is None or (isinstance(v, float) and np.isnan(v)) else f"{100 * v:.2f}%"


def write_report(path: Path, meta: dict) -> None:
    ev, t = meta["evaluation"], meta["thresholds"]
    test, ch = ev["test"], ev.get("challenge")
    lines = [
        f"# PE model {meta['model_version']}",
        "",
        f"Quality gate: **{'PASSED' if meta['quality_gate']['passed'] else 'FAILED'}**"
        + ("" if meta["quality_gate"]["passed"] else " (the engine will treat this model as advisory)"),
        "",
        "## Data and split (by time, oldest first)",
        "",
        "| Part | Rows | Malicious | Dates | Used for |",
        "|---|---:|---:|---|---|",
    ]
    for part, use in [("fit", "training the trees"), ("valid", "early stopping"), ("calib", "calibration and thresholds"), ("test", "this report only")]:
        p = ev["splits"][part]
        dr = p.get("date_range") or ["", ""]
        lines.append(f"| {part} | {p['rows']:,} | {p['malicious']:,} | {dr[0]} to {dr[1]} | {use} |")
    lines += [
        "",
        "## Results on the test weeks",
        "",
        f"- ROC AUC: {test.get('auc', float('nan')):.4f}",
        f"- Malicious threshold (set at {_pct(t['malicious_fpr_target'])} false positives on the calibration weeks): "
        f"detects {_pct(test['at_malicious_threshold']['tpr'])} of malware, "
        f"false positives {_pct(test['at_malicious_threshold']['fpr'])}",
        f"- Suspicious threshold (set at {_pct(t['suspicious_fpr_target'])}): "
        f"detects {_pct(test['at_suspicious_threshold']['tpr'])}, "
        f"false positives {_pct(test['at_suspicious_threshold']['fpr'])}",
        f"- Detection at 0.1% false positives if tuned on the test data itself (comparison only): {_pct(test.get('oracle_tpr_at_0.1pct_fpr'))}",
        f"- Calibration: ECE {test.get('ece', float('nan')):.4f}, Brier {test.get('brier', float('nan')):.4f}",
        "",
    ]
    if ch:
        lines += [
            "## Challenge set (evasive malware)",
            "",
            f"- Detected at the malicious threshold: {_pct(ch['at_malicious_threshold']['tpr'])} of {ch['malicious']:,}",
            f"- Detected at the suspicious threshold: {_pct(ch['at_suspicious_threshold']['tpr'])}",
            "",
        ]
    lines += ["## Calibration on the test weeks", "", "| Score | Files | Mean score | Actually malicious |", "|---|---:|---:|---:|"]
    for r in test.get("reliability", []):
        if r["count"]:
            lines.append(f"| {r['bin']} | {r['count']:,} | {r['mean_score']:.3f} | {r['malicious_rate']:.3f} |")
    lines += ["", "## Drift by month (malicious threshold)", "", "| Month | Detection | False positives |", "|---|---:|---:|"]
    for r in test.get("by_month", []):
        lines.append(f"| {r['period']} | {_pct(r['tpr'])} | {_pct(r['fpr'])} |")
    if test.get("by_file_type"):
        lines += ["", "## By file type", "", "| Type | Detection | False positives |", "|---|---:|---:|"]
        for r in test["by_file_type"]:
            lines.append(f"| {r['file_type']} | {_pct(r['tpr'])} | {_pct(r['fpr'])} |")
    if test.get("families"):
        lines += ["", "## Largest malware families in the test weeks", "", "| Family | Files | Detected |", "|---|---:|---:|"]
        for r in test["families"]:
            lines.append(f"| {r['family']} | {r['count']:,} | {_pct(r['detected'])} |")
    lines += ["", "## Quality gate", ""]
    for c in meta["quality_gate"]["checks"]:
        v = c["value"]
        lines.append(f"- {'PASS' if c['passed'] else 'FAIL'}: {c['check']} (got {v if v is None else round(v, 5)})")
    lines += [
        "",
        f"Trees: {meta['training']['num_trees']}. Model file: {meta['training']['model_bytes'] / 1e6:.1f} MB. "
        f"Trained in {meta['training']['seconds'] / 60:.1f} min.",
        "",
    ]
    path.write_text("\n".join(lines))


def train(args: argparse.Namespace) -> dict:
    import lightgbm as lgb

    data_dir, out_dir = Path(args.data_dir).expanduser(), Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = Path(args.cache_dir).expanduser() if args.cache_dir else data_dir / "verdyx_cache"
    file_types = tuple(args.file_types.split(","))

    if args.download:
        download(data_dir)

    _log("building training features")
    tr = dataset.build(dataset.find_files(data_dir, "train", file_types), cache / "train",
                       fraction=args.train_sample, file_types=(), workers=args.workers, log=_log)
    _log("building test features")
    te = dataset.build(dataset.find_files(data_dir, "test", file_types), cache / "test",
                       fraction=args.test_sample, file_types=(), workers=args.workers, log=_log)
    challenge_files = dataset.find_files(data_dir, "challenge", file_types)
    ch = None
    if challenge_files:
        _log("building challenge-set features")
        ch = dataset.build(challenge_files, cache / "challenge", file_types=file_types, workers=args.workers, log=_log)
        if not len(ch):
            _log(f"  warning: no challenge rows have file_type in {file_types}; skipping it")
            ch = None

    fit_end, valid_end = time_split(len(tr), args.valid_frac, args.calib_frac)
    fit, valid, calib = tr.slice(0, fit_end), tr.slice(fit_end, valid_end), tr.slice(valid_end, len(tr))
    overlap = bool(len(te) and te.date.min() < calib.date.max())
    for name, part in [("fit", fit), ("valid", valid), ("calib", calib), ("test", te)]:
        _log(f"  {name}: {len(part):,} rows, {int(part.y.sum()):,} malicious, "
             f"{_iso(part.date.min())} to {_iso(part.date.max())}")
    if overlap:
        _log("  note: some test files predate the newest calibration files")

    params = {**DEFAULT_PARAMS, "num_threads": args.workers or os.cpu_count() or 1}
    if args.num_leaves:
        params["num_leaves"] = args.num_leaves
    if args.learning_rate:
        params["learning_rate"] = args.learning_rate
    if args.min_data_in_leaf:
        params["min_data_in_leaf"] = args.min_data_in_leaf

    _log("training LightGBM")
    started = time.time()
    dtrain = lgb.Dataset(fit.X, label=fit.y, categorical_feature=CATEGORICAL_FEATURES, free_raw_data=True)
    dvalid = lgb.Dataset(valid.X, label=valid.y, reference=dtrain, categorical_feature=CATEGORICAL_FEATURES)
    booster = lgb.train(
        params, dtrain, num_boost_round=args.max_rounds, valid_sets=[dvalid], valid_names=["valid"],
        callbacks=[lgb.early_stopping(args.early_stopping, verbose=False), lgb.log_evaluation(100)],
    )
    seconds = time.time() - started
    _log(f"  {booster.best_iteration or booster.num_trees()} trees in {seconds / 60:.1f} min")
    if booster.best_iteration:
        booster = lgb.Booster(model_str=booster.model_to_string(num_iteration=booster.best_iteration))

    _log("calibrating and setting thresholds on the calibration weeks")
    calib_raw = predict(booster, calib.X)
    calibrator = fit_isotonic(calib_raw, calib.y)
    thresholds = {name: metrics.threshold_at_fpr(calib.y, calib_raw, fpr) for name, fpr in THRESHOLDS_FPR.items()}
    if thresholds["suspicious"] > thresholds["malicious"]:
        thresholds["suspicious"] = thresholds["malicious"]

    _log("evaluating on the test weeks")
    test_eval = evaluate(booster, calibrator, thresholds, te)
    challenge_eval = evaluate(booster, calibrator, thresholds, ch) if ch is not None and len(ch) else None
    gate = quality_gate(test_eval, {**DEFAULT_GATE, **{k: v for k, v in vars(args).items() if k in DEFAULT_GATE and v is not None}})

    version = args.version or datetime.now(timezone.utc).strftime("pe-%Y%m%d-%H%M")
    model_path = out_dir / MODEL_FILE
    booster.save_model(str(model_path))
    (out_dir / CALIBRATION_FILE).write_text(json.dumps(calibrator.to_json()) + "\n")

    def part(s: dataset.Split) -> dict:
        return {"rows": len(s), "malicious": int(s.y.sum()),
                "date_range": [_iso(s.date.min()), _iso(s.date.max())] if len(s) else None}

    meta = {
        "model_version": version,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "trainer": f"verdyx_ml {__version__}",
        "dataset": "EMBER2024",
        "file_types": list(file_types),
        "thresholds": {
            "malicious": thresholds["malicious"],
            "suspicious": thresholds["suspicious"],
            "malicious_fpr_target": THRESHOLDS_FPR["malicious"],
            "suspicious_fpr_target": THRESHOLDS_FPR["suspicious"],
            "malicious_probability": float(calibrator(thresholds["malicious"])),
            "suspicious_probability": float(calibrator(thresholds["suspicious"])),
        },
        "evaluation": {
            "splits": {"fit": part(fit), "valid": part(valid), "calib": part(calib), "test": part(te)},
            "test_predates_calibration": overlap,
            "test": test_eval,
            "challenge": challenge_eval,
            "skipped_records": {"train": tr.errors, "test": te.errors},
        },
        "quality_gate": gate,
        "training": {
            "params": params,
            "num_trees": booster.num_trees(),
            "seconds": seconds,
            "model_bytes": model_path.stat().st_size,
            "train_sample": args.train_sample,
            "test_sample": args.test_sample,
        },
    }
    write_meta(out_dir, meta)
    write_report(out_dir / REPORT_FILE, {**meta})
    _log(f"wrote {out_dir} (quality gate {'passed' if gate['passed'] else 'FAILED'})")
    return meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", required=True, help="where EMBER2024 .jsonl files are (or will be downloaded)")
    p.add_argument("--out-dir", required=True, help="where to write the model bundle")
    p.add_argument("--download", action="store_true", help="download EMBER2024 PE data first (~30 GB)")
    p.add_argument("--cache-dir", help="where to keep vectorized features (default: <data-dir>/verdyx_cache)")
    p.add_argument("--file-types", default=",".join(dataset.PE_FILE_TYPES), help="comma list of Win32,Win64,Dot_Net")
    p.add_argument("--train-sample", type=float, default=1.0,
                   help="fraction of training files to keep (by sha256). 0.5 fits in ~16 GB RAM")
    p.add_argument("--test-sample", type=float, default=1.0)
    p.add_argument("--valid-frac", type=float, default=0.08)
    p.add_argument("--calib-frac", type=float, default=0.12)
    p.add_argument("--max-rounds", type=int, default=3000)
    p.add_argument("--early-stopping", type=int, default=100)
    p.add_argument("--num-leaves", type=int)
    p.add_argument("--learning-rate", type=float)
    p.add_argument("--min-data-in-leaf", type=int)
    p.add_argument("--workers", type=int)
    p.add_argument("--version", help="model version label (default: pe-YYYYMMDD-HHMM)")
    for k, v in DEFAULT_GATE.items():
        p.add_argument("--" + k.replace("_", "-"), dest=k, type=float, help=f"quality gate (default {v})")
    args = p.parse_args(argv)
    meta = train(args)
    return 0 if meta["quality_gate"]["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
