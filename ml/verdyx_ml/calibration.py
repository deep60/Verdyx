"""Isotonic calibration: map raw model scores to real probabilities.

LightGBM scores rank files well but are not probabilities: 0.9 does not mean
"90% likely malicious". Isotonic regression learns a monotone step function
from raw score to observed malicious rate on held-out data, so the order of
files is kept and only the scale changes.

The fitted function is stored as plain breakpoints, so serving needs only
numpy (no scikit-learn model pickle).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

# Keep probabilities strictly inside (0, 1): no engine should claim certainty.
_EPS = 1e-4


@dataclass(frozen=True)
class IsotonicCalibrator:
    x: tuple[float, ...]  # raw-score breakpoints, increasing
    y: tuple[float, ...]  # calibrated probability at each breakpoint

    def __call__(self, raw: np.ndarray | float) -> np.ndarray:
        out = np.interp(np.asarray(raw, dtype=np.float64), self.x, self.y)
        return np.clip(out, _EPS, 1.0 - _EPS)

    def to_json(self) -> dict:
        return {"method": "isotonic", "x": list(self.x), "y": list(self.y)}

    @classmethod
    def from_json(cls, obj: dict) -> "IsotonicCalibrator":
        if obj.get("method") != "isotonic":
            raise ValueError(f"unsupported calibration method {obj.get('method')!r}")
        x, y = tuple(float(v) for v in obj["x"]), tuple(float(v) for v in obj["y"])
        if len(x) != len(y) or len(x) < 2:
            raise ValueError("calibration needs at least two matching breakpoints")
        if any(b < a for a, b in zip(x, x[1:])) or any(b < a for a, b in zip(y, y[1:])):
            raise ValueError("calibration breakpoints must be non-decreasing")
        return cls(x, y)


def fit_isotonic(raw: np.ndarray, y: np.ndarray) -> IsotonicCalibrator:
    """Fit on held-out data the model was not trained on."""
    from sklearn.isotonic import IsotonicRegression  # training-time only

    raw = np.asarray(raw, dtype=np.float64)
    y = np.asarray(y, dtype=np.float64)
    if len(np.unique(y)) < 2:
        raise ValueError("calibration data needs both malicious and clean files")
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
    iso.fit(raw, y)
    x = np.asarray(iso.X_thresholds_, dtype=np.float64)
    yy = np.asarray(iso.y_thresholds_, dtype=np.float64)
    if len(x) < 2:  # a single step: widen it so interpolation is defined
        x = np.array([0.0, 1.0])
        yy = np.array([yy[0], yy[0]])
    return IsotonicCalibrator(tuple(x.tolist()), tuple(yy.tolist()))
