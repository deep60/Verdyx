# Consensus Specification & Explainability Guide

This document details the verdict calculation mathematical model, vote weighting, handling of unavailable analyzers, and auditable history retention for the Verdyx platform.

---

## 1. Principles of Consensus Formulation

1. **Exclusivity of Active Engines**: Only engines that successfully execute and return an affirmative verdict (`Malicious`, `Benign`, or `Suspicious`) participate in consensus grading.
2. **Fail-Closed on Engine Availability**: If an engine encounters an error, daemon timeout, or missing rule file, it records an explicit `Unavailable` status. It is **never** counted as a vote for `Benign` or `Clean`.
3. **Calibrated Concordance Over Fake Probabilities**: Confidence is reported as a calibrated agreement index between $0\%$ and $100\%$, measuring concordance among participating engines. It is **not** presented as an uncalibrated Bayesian posterior probability.
4. **Immutable Audit History**: Any adjustment to a verdict—whether through engine re-evaluation, multi-round commit-reveal voting, or regrader dispute resolution—is appended to an immutable audit record.

---

## 2. Vote Weighting and Verdict Calculation

### 2.1 Engine Weights
Each engine is assigned an effective vote weight $w_i \in (0.0, 1.0]$ based on its historical accuracy, verification rigor, and stake:

$$\text{Weight}(i) = \text{base\_weight}_i \times \text{reputation\_factor}_i$$

| Engine Class | Default Base Weight | Rationale |
| :--- | :--- | :--- |
| **YARA / Signature Matcher** | $1.0$ | Exact pattern or cryptographic hash match with minimal false positive variance. |
| **Heuristic Engine** | $0.8$ | Behavioral regex indicators with potential environmental overlap. |
| **ClamAV Antivirus** | $0.9$ | Multi-vendor signature catalog. |
| **Machine Learning (ONNX)** | $0.75$ | Statistical model classification requiring threshold gating. |
| **Static Binary Analyzer** | $0.7$ | Structural inspection of sections, imports, and entropy. |

### 2.2 Aggregation Formula
For an active submission with participating engines $P = \{1, \dots, N\}$:

1. **Vote Grouping**:
   $$W_{\text{malicious}} = \sum_{i \in P, v_i = \text{Malicious}} w_i \times c_i$$
   $$W_{\text{suspicious}} = \sum_{i \in P, v_i = \text{Suspicious}} w_i \times c_i$$
   $$W_{\text{benign}} = \sum_{i \in P, v_i = \text{Benign}} w_i \times c_i$$
   where $c_i \in [0.0, 1.0]$ is engine $i$'s confidence score for its finding.

2. **Verdict Decision**:
   $$\text{Final Verdict} = \begin{cases}
     \text{Malicious}, & \text{if } W_{\text{malicious}} \ge W_{\text{suspicious}} \text{ and } W_{\text{malicious}} \ge W_{\text{benign}} \text{ and } W_{\text{malicious}} > 0 \\
     \text{Suspicious}, & \text{if } W_{\text{suspicious}} > W_{\text{benign}} \text{ and } W_{\text{suspicious}} > 0 \\
     \text{Benign}, & \text{if } W_{\text{benign}} > 0 \\
     \text{Unknown}, & \text{if } |P| = 0
   \end{cases}$$

3. **Agreement Concordance Score**:
   $$\text{Agreement Score} = \frac{\max(V_{\text{malicious}}, V_{\text{suspicious}}, V_{\text{benign}})}{|P|} \times 100\%$$
   where $V_x$ represents the unweighted vote count for outcome $x$.

---

## 3. Impact of Unavailable or Failed Engines

When an engine fails (e.g. ClamAV daemon is unreachable on port 3310):
- **Vote Exclusion**: The failed engine is removed from the active voter pool $P$. It contributes 0 weight to both malicious and benign vote tallies.
- **Explainability Reporting**: The engine is recorded in `unavailable_engines` with the specific root cause (e.g., `"clamd daemon unreachable on localhost:3310"`).
- **Consensus Explanation**: The generated human-readable explanation explicitly notes the exclusion:
  > *"Verdict: Malicious with 66.7% agreement (2/3 active engines: signature_matcher, heuristic_engine). 1 engine(s) (clamav) were unavailable and excluded from consensus."*

---

## 4. Confidence vs. Probability Calibration

In security telemetry, presenting a score as a "probability of infection" without empirical Bayesian prior calibration is misleading.
Verdyx enforces the following:
1. **API Responses**: Always include `agreementScore` alongside `confidenceScore`.
2. **Explanatory Disclaimer**:
   > *"Agreement score reflects weighted concordance across participating engines (0-100%), not an uncalibrated Bayesian posterior probability."*
3. **Frontend UI**: Visualizes consensus strength using categorized bands:
   - **Strong Consensus**: $\ge 90\%$ agreement
   - **Moderate Consensus**: $75\% - 89\%$ agreement
   - **Weak / Split Consensus**: $< 75\%$ agreement

---

## 5. Auditable History & Delayed Regrading

When a sample verdict is adjusted (e.g. during a decentralized dispute or when a delayed sandbox analysis finishes):
1. **Audit Record Structure**:
   ```json
   {
     "verdict": "Malicious",
     "confidence": 85.5,
     "reason": "Regrader confirmed malicious payload following dispute #42",
     "changedBy": "regrader_worker",
     "changedAt": "2026-10-09T14:30:00Z"
   }
   ```
2. **Non-Destructive Storage**: Evidence, raw detections, and individual engine findings are never overwritten. A new entry is appended to `verdict_history`.
3. **API & UI Visibility**: The entire progression of verdicts from initial submission to final regraded state is inspectable through `/api/v1/submissions/:id/consensus`.
