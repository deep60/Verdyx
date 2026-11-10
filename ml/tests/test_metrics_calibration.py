import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from verdyx_ml import metrics
from verdyx_ml.calibration import IsotonicCalibrator, fit_isotonic


def _data(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    y = rng.random(n) < 0.4
    score = np.where(y, rng.beta(5, 2, n), rng.beta(2, 5, n))
    return y.astype(int), score


def test_auc_matches_sklearn_with_ties():
    y, s = _data()
    s = np.round(s, 2)  # force ties
    assert metrics.roc_auc(y, s) == pytest.approx(roc_auc_score(y, s), abs=1e-12)


@pytest.mark.parametrize("fpr", [0.001, 0.01, 0.1])
def test_threshold_respects_the_false_positive_target(fpr):
    y, s = _data()
    t = metrics.threshold_at_fpr(y, s, fpr)
    got = metrics.rates_at(y, s, t)
    assert got["fpr"] <= fpr
    # And it is the lowest such threshold: one clean file more would break it.
    neg = np.sort(s[y == 0])[::-1]
    allowed = int(np.floor(fpr * len(neg)))
    assert metrics.rates_at(y, s, neg[allowed])["false_positives"] > allowed


def test_ece_is_zero_for_a_calibrated_score_and_large_otherwise():
    rng = np.random.default_rng(1)
    p = rng.random(200_000)
    y = (rng.random(len(p)) < p).astype(int)
    assert metrics.expected_calibration_error(y, p) < 0.01
    assert metrics.expected_calibration_error(y, p ** 4) > 0.1


def test_isotonic_calibration_fixes_a_distorted_score():
    rng = np.random.default_rng(2)
    p = rng.random(50_000)
    y = (rng.random(len(p)) < p).astype(int)
    distorted = p ** 3
    cal = fit_isotonic(distorted, y)
    fixed = cal(distorted)
    assert metrics.expected_calibration_error(y, fixed) < 0.02
    assert np.all(np.diff(cal(np.linspace(0, 1, 500))) >= 0)  # monotone
    assert 0 < fixed.min() and fixed.max() < 1  # never claims certainty


def test_calibration_round_trips_and_rejects_bad_input():
    cal = IsotonicCalibrator((0.0, 0.5, 1.0), (0.1, 0.4, 0.9))
    again = IsotonicCalibrator.from_json(cal.to_json())
    assert again(0.25) == pytest.approx(0.25)
    with pytest.raises(ValueError):
        IsotonicCalibrator.from_json({"method": "isotonic", "x": [0, 1], "y": [0.9, 0.1]})
    with pytest.raises(ValueError):
        IsotonicCalibrator.from_json({"method": "platt", "x": [0, 1], "y": [0, 1]})
