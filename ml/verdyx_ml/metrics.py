"""Evaluation metrics, written for malware detection rather than accuracy.

A detector is judged by how many malicious files it catches while keeping
false alarms on clean software rare. So the headline numbers are the detection
rate (TPR) at a fixed false-positive rate, such as 0.1%, and the threshold is
chosen on one dataset and then *reported on a later one*, never tuned on the
data it is scored on.

Calibration is measured too: a score of 0.9 should mean the file is malicious
about 90% of the time, so scores from different engines combine fairly.
"""

from __future__ import annotations

import numpy as np


def roc_auc(y: np.ndarray, score: np.ndarray) -> float:
    """Area under the ROC curve (rank-based, ties averaged)."""
    y = np.asarray(y).astype(bool)
    score = np.asarray(score, dtype=np.float64)
    n_pos, n_neg = int(y.sum()), int((~y).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(score, kind="mergesort")
    ranks = np.empty(len(score), dtype=np.float64)
    sorted_scores = score[order]
    # Average ranks over ties.
    i = 0
    while i < len(sorted_scores):
        j = i
        while j + 1 < len(sorted_scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((ranks[y].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def threshold_at_fpr(y: np.ndarray, score: np.ndarray, fpr: float) -> float:
    """The lowest threshold whose false-positive rate is at most `fpr`.

    A file is called malicious when its score is >= the threshold. With n
    clean files, at most floor(fpr * n) of them may score at or above it.
    """
    y = np.asarray(y).astype(bool)
    neg = np.sort(np.asarray(score, dtype=np.float64)[~y])[::-1]
    if len(neg) == 0:
        raise ValueError("no clean samples to set a false-positive threshold")
    allowed = int(np.floor(fpr * len(neg)))
    if allowed >= len(neg):
        return float(neg[-1])
    # Just above the (allowed)-th highest clean score, so exactly `allowed`
    # clean files (or fewer, with ties) reach the threshold.
    return float(np.nextafter(neg[allowed], np.inf))


def rates_at(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    y = np.asarray(y).astype(bool)
    flagged = np.asarray(score) >= threshold
    pos, neg = int(y.sum()), int((~y).sum())
    tp = int((flagged & y).sum())
    fp = int((flagged & ~y).sum())
    return {
        "threshold": float(threshold),
        "tpr": tp / pos if pos else float("nan"),
        "fpr": fp / neg if neg else float("nan"),
        "true_positives": tp,
        "false_positives": fp,
        "malicious": pos,
        "benign": neg,
    }


def brier(y: np.ndarray, prob: np.ndarray) -> float:
    y = np.asarray(y, dtype=np.float64)
    prob = np.asarray(prob, dtype=np.float64)
    return float(np.mean((prob - y) ** 2))


def reliability(y: np.ndarray, prob: np.ndarray, bins: int = 10) -> list[dict]:
    """Per score bin: how often files there were actually malicious."""
    y = np.asarray(y, dtype=np.float64)
    prob = np.asarray(prob, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(prob, edges[1:-1], right=False), 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        n = int(m.sum())
        out.append(
            {
                "bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}",
                "count": n,
                "mean_score": float(prob[m].mean()) if n else None,
                "malicious_rate": float(y[m].mean()) if n else None,
            }
        )
    return out


def expected_calibration_error(y: np.ndarray, prob: np.ndarray, bins: int = 10) -> float:
    """Average gap between score and observed malicious rate, weighted by bin size."""
    total = len(prob)
    if total == 0:
        return float("nan")
    ece = 0.0
    for row in reliability(y, prob, bins):
        if row["count"]:
            ece += row["count"] / total * abs(row["mean_score"] - row["malicious_rate"])
    return float(ece)
