# ML Models (`threat_classifier.onnx` & `anomaly_detector.onnx`)

> **Not trained on data.** `scripts/train_onnx_models.py` sets these weights by hand from byte-distribution rules. In testing the classifier called ordinary ZIP, PNG, gzip and executable files malicious at 0.94–1.00. Treat its verdict as a weak signal until it is replaced by a model trained on a labelled dataset.

The `analysis-engine` ML analyzer loads two hand-calibrated ONNX models (IR v8, Opset 13) from this directory:

| File | Role | Shape Contract | Env Override |
| :--- | :--- | :--- | :--- |
| `threat_classifier.onnx` (~35 KB) | 2-layer MLP (`259 -> 32 -> 10` + `Softmax`) multi-class threat classifier | Input: `float32 [1, 259]` · Output: `float32 [1, 10]` | `ML_CLASSIFIER_MODEL` |
| `anomaly_detector.onnx` (~17 KB) | 2-layer MLP (`259 -> 16 -> 1` + `Sigmoid`) byte-distribution anomaly detector | Input: `float32 [1, 259]` · Output: `float32 [1, 1]` | `ML_ANOMALY_MODEL` |

## Feature Vector Contract (`DEFAULT_FEATURE_SIZE = 259`)

`MlAnalyzer::extract_features` (`src/analyzers/ml_analyzer.rs`) emits 259 `float32` values in order:

```text
[ size_norm, entropy/8.0, printable_ratio, <256-bin normalized byte-frequency histogram> ]
  \______________ 3 scalars _____________/  \________________ 256 bins ________________/
```

### Classifier Output Classes (`[1, 10]`)

Index-aligned with `MlAnalyzerConfig::labels`:
0. `benign`
1. `malware`
2. `trojan`
3. `ransomware`
4. `adware`
5. `spyware`
6. `rootkit`
7. `backdoor`
8. `worm`
9. `virus`

## Rebuilding the ONNX Models

Run the zero-dependency export script from the repository root:

```bash
python3 scripts/train_onnx_models.py
```
