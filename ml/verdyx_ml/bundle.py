"""The on-disk model bundle shared by training and serving.

A bundle is a directory:

    model.txt         LightGBM model (text format)
    calibration.json  isotonic breakpoints, raw score -> probability
    bundle.json       thresholds, evaluation results, quality gate, provenance
    report.md         the same evaluation, written for people

Serving refuses a bundle whose feature layout or format version does not match
this code, rather than scoring files with features the model was not trained on.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .calibration import IsotonicCalibrator
from .pe_features import FEATURE_DIM, FEATURE_VERSION, feature_infos

BUNDLE_FORMAT = 1
MODEL_FILE = "model.txt"
CALIBRATION_FILE = "calibration.json"
META_FILE = "bundle.json"
REPORT_FILE = "report.md"


def feature_layout_hash() -> str:
    """Fingerprint of the feature layout (names and order)."""
    h = hashlib.sha256()
    for info in feature_infos():
        h.update(f"{info.index}\t{info.group}\t{info.name}\n".encode())
    return h.hexdigest()[:16]


@dataclass(frozen=True)
class Thresholds:
    """Raw-score cut-offs. A score >= `malicious` is flagged malicious."""

    malicious: float  # set at the strict false-positive target (e.g. 0.1%)
    suspicious: float  # set at the looser target (e.g. 1%)
    malicious_fpr_target: float
    suspicious_fpr_target: float


@dataclass(frozen=True)
class BundleMeta:
    raw: dict

    @property
    def version(self) -> str:
        return self.raw["model_version"]

    @property
    def thresholds(self) -> Thresholds:
        t = self.raw["thresholds"]
        return Thresholds(
            malicious=float(t["malicious"]),
            suspicious=float(t["suspicious"]),
            malicious_fpr_target=float(t["malicious_fpr_target"]),
            suspicious_fpr_target=float(t["suspicious_fpr_target"]),
        )

    @property
    def quality_gate_passed(self) -> bool:
        return bool(self.raw.get("quality_gate", {}).get("passed"))


def write_meta(out_dir: Path, meta: dict) -> None:
    meta = {
        **meta,
        "bundle_format": BUNDLE_FORMAT,
        "feature_version": FEATURE_VERSION,
        "feature_dim": FEATURE_DIM,
        "feature_layout": feature_layout_hash(),
    }
    (out_dir / META_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")


def read_meta(bundle_dir: Path) -> BundleMeta:
    meta = json.loads((bundle_dir / META_FILE).read_text())
    if meta.get("bundle_format") != BUNDLE_FORMAT:
        raise ValueError(f"bundle format {meta.get('bundle_format')} is not {BUNDLE_FORMAT}")
    if meta.get("feature_dim") != FEATURE_DIM or meta.get("feature_version") != FEATURE_VERSION:
        raise ValueError("bundle was trained on a different feature set")
    if meta.get("feature_layout") != feature_layout_hash():
        raise ValueError("bundle feature layout does not match this extractor")
    return BundleMeta(meta)


def read_calibration(bundle_dir: Path) -> IsotonicCalibrator:
    return IsotonicCalibrator.from_json(json.loads((bundle_dir / CALIBRATION_FILE).read_text()))
