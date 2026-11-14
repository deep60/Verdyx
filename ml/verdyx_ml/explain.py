"""Explain a verdict with exact SHAP values.

LightGBM computes TreeSHAP natively (`pred_contrib=True`): for each feature, how
much it pushed this file's score toward malicious (positive) or clean
(negative), in log-odds, adding up exactly to the model's raw output. No
sampling and no separate explainer model.

Contributions are then made readable. Hashed features name the actual imports,
sections and exports from this file that fell into the bucket, and the largest
pushes are summed by group ("imports", "sections", ...) for a one-line summary.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from .pe_features import FeatureInfo, bucket_tokens, feature_infos

GROUP_LABELS = {
    "general": "file size and entropy",
    "histogram": "byte distribution",
    "byteentropy": "byte entropy profile",
    "strings": "embedded strings",
    "header": "PE header",
    "section": "sections",
    "imports": "imported functions",
    "exports": "exported functions",
    "datadirectories": "data directories",
    "richheader": "Rich header (build toolchain)",
    "authenticode": "code signature",
    "pefilewarnings": "malformed-structure warnings",
}


def _value_text(info: FeatureInfo, value: float) -> str:
    if info.hashed is not None:
        return ""
    if "entropy" in info.name and "local entropy" not in info.name:
        return f"{value:.2f} bits"
    if info.name.startswith(("share of", "max section size", "min section size")) or "ratio" in info.name:
        return f"{value:.3f}"
    if float(value).is_integer():
        return f"{int(value)}"
    return f"{value:.3g}"


def _describe(info: FeatureInfo, value: float, raw: dict) -> str:
    if info.hashed is not None:
        tokens = bucket_tokens(raw, info)
        if tokens:
            kind = info.name.rsplit(" bucket ", 1)[0]
            return f"{kind}: {', '.join(tokens)}"
        # No name from this file hashes here: the bucket being empty is the signal.
        return f"{info.name} (absent in this file)"
    v = _value_text(info, value)
    return f"{info.name} = {v}" if v else info.name


def explain(
    contributions: np.ndarray,
    vector: np.ndarray,
    raw: dict,
    top_k: int = 8,
) -> dict[str, Any]:
    """Turn one row of `pred_contrib` output into reasons.

    `contributions` has FEATURE_DIM + 1 values; the last is the bias (the
    model's average output), so bias + sum(features) == raw log-odds.
    """
    infos = feature_infos()
    contrib = np.asarray(contributions, dtype=np.float64).ravel()
    bias, feats = float(contrib[-1]), contrib[:-1]
    if len(feats) != len(infos):
        raise ValueError(f"expected {len(infos)} contributions, got {len(feats)}")

    order = np.argsort(-np.abs(feats))
    reasons = []
    for i in order[:top_k]:
        c = float(feats[i])
        if c == 0.0:
            break
        info = infos[i]
        reasons.append(
            {
                "feature": info.name,
                "group": info.group,
                "description": _describe(info, float(vector[i]), raw),
                "value": float(vector[i]),
                "contribution": round(c, 4),
                "direction": "malicious" if c > 0 else "benign",
            }
        )

    groups: dict[str, float] = {}
    for info, c in zip(infos, feats):
        if c:
            groups[info.group] = groups.get(info.group, 0.0) + float(c)
    group_list = sorted(
        (
            {"group": g, "label": GROUP_LABELS.get(g, g), "contribution": round(v, 4)}
            for g, v in groups.items()
        ),
        key=lambda r: -abs(r["contribution"]),
    )

    pushing = [r for r in reasons if r["direction"] == "malicious"][:3]
    if pushing:
        summary = "Main reasons: " + "; ".join(r["description"] for r in pushing)
    else:
        summary = "Nothing in the file pushed the score toward malicious"

    return {
        "method": "TreeSHAP (LightGBM pred_contrib), log-odds of the raw model score",
        "base_value": round(bias, 4),
        "raw_log_odds": round(bias + float(feats.sum()), 4),
        "summary": summary,
        "reasons": reasons,
        "groups": group_list[:6],
    }
