# Phase 9 - Experimental Evaluation Report
## Intent-Aware Deception System for Real-Time Attacker Profiling - v1.0 RC

---

## Task 11 - Reproducibility: Evaluation Environment

| Parameter | Value |
| :--- | :--- |
| Evaluation Date/Time | 2026-08-19T18:21:05.253192+00:00 |
| Software Version | v1.0 Release Candidate |
| Python Version | 3.12.9 |
| Total Test Cases | 42 |
| Intent Categories | 10 |
| Gemini Model | gemini-2.5-flash |
| Gemini Enabled | Checked at runtime (GEMINI_ENABLED env var) |
| Rule Engine | Deterministic regex + event-type matching |
| Metric Averaging | Macro (unweighted) and Weighted (support-weighted) |
| Cowrie Version | 3.0.12 (WSL2 Ubuntu) |
| Platform | Windows 11 + WSL2 Ubuntu |
| MongoDB | 7.x (local) |
| API Framework | FastAPI 0.115+ |
| Note | No production code was modified during evaluation. |

---

## Task 1 - Implemented Intent Taxonomy

The following 10 intent categories are implemented in the frozen v1.0 classifier
([`backend/app/models/intent.py`](../../backend/app/models/intent.py),
[`backend/app/services/rule_classifier.py`](../../backend/app/services/rule_classifier.py)):

| # | Intent Category | MITRE ATT&CK Mapping | Rule IDs |
| :--- | :--- | :--- | :--- |
| 1 | RECONNAISSANCE | Reconnaissance (TA0043) | RULE_RECON_01 |
| 2 | DISCOVERY | Discovery (TA0007) | RULE_DISC_01 |
| 3 | CREDENTIAL_ACCESS | Credential Access (TA0006) | RULE_CRED_01, RULE_CRED_02 |
| 4 | EXECUTION | Execution (TA0002) | RULE_EXEC_01, RULE_EXEC_02 |
| 5 | PRIVILEGE_ESCALATION | Privilege Escalation (TA0004) | RULE_PRIVESC_01, RULE_PRIVESC_02 |
| 6 | PERSISTENCE | Persistence (TA0003) | RULE_PERSIST_01, RULE_PERSIST_02 |
| 7 | EXPLOITATION | Execution (TA0002) | RULE_EXPLOIT_01 |
| 8 | EXFILTRATION | Exfiltration (TA0010) | RULE_EXFIL_01 |
| 9 | CLEANUP | Defense Evasion (TA0005) | RULE_CLEAN_01 |
| 10 | OTHER | Initial Access / Unknown | Fallback |

---

## Task 4 - Intent Classification Results

**Averaging method**: Macro averages are computed as unweighted arithmetic means across all classes
present in the ground truth. Weighted averages are computed as support-weighted means.

### Aggregate Metrics

| Metric | Value |
| :--- | ---: |
| Accuracy | **1.0000** |
| Macro Precision | 1.0000 |
| Macro Recall | 1.0000 |
| Macro F1 | 1.0000 |
| Weighted Precision | 1.0000 |
| Weighted Recall | 1.0000 |
| Weighted F1 | 1.0000 |
| Total Cases | 42 |

### Per-Class Metrics (Intent | Precision | Recall | F1 | Support)

| Intent | Precision | Recall | F1 | Support |
| :--- | ---: | ---: | ---: | ---: |
| CLEANUP | 1.0000 | 1.0000 | 1.0000 | 4 |
| CREDENTIAL_ACCESS | 1.0000 | 1.0000 | 1.0000 | 5 |
| DISCOVERY | 1.0000 | 1.0000 | 1.0000 | 5 |
| EXECUTION | 1.0000 | 1.0000 | 1.0000 | 5 |
| EXFILTRATION | 1.0000 | 1.0000 | 1.0000 | 4 |
| EXPLOITATION | 1.0000 | 1.0000 | 1.0000 | 3 |
| OTHER | 1.0000 | 1.0000 | 1.0000 | 4 |
| PERSISTENCE | 1.0000 | 1.0000 | 1.0000 | 4 |
| PRIVILEGE_ESCALATION | 1.0000 | 1.0000 | 1.0000 | 4 |
| RECONNAISSANCE | 1.0000 | 1.0000 | 1.0000 | 4 |

---

## Task 5 - Attack Stage Classification

| Metric | Value |
| :--- | ---: |
| Accuracy | 1.0000 |
| Macro Precision | 1.0000 |
| Macro Recall | 1.0000 |
| Macro F1 | 1.0000 |
| Weighted F1 | 1.0000 |

> **Note**: Attack stage labels in this system are deterministically derived from rule matches.
> The stage evaluation is therefore tightly correlated with intent evaluation; it does not
> represent an independent classification axis.

---

## Task 6 — Risk Score Analysis

> **Important**: Risk weights are project-defined constants in `risk_engine.py`.
> They were **not modified** during this evaluation.

| Metric | Value |
| :--- | ---: |
| Minimum Risk Score | 0 |
| Maximum Risk Score | 35 |
| Average Risk Score | 20.83 |

**Severity Distribution:**

| Severity Tier | Count |
| :--- | ---: |
| LOW | 22 |
| MEDIUM | 20 |

**Average Risk Score by Intent:**

| Intent | Min | Avg | Max | Cases |
| :--- | ---: | ---: | ---: | ---: |
| CLEANUP | 15 | 15.0 | 15 | 4 |
| CREDENTIAL_ACCESS | 25 | 26.0 | 30 | 5 |
| DISCOVERY | 15 | 15.0 | 15 | 5 |
| EXECUTION | 20 | 20.0 | 20 | 5 |
| EXFILTRATION | 35 | 35.0 | 35 | 4 |
| EXPLOITATION | 30 | 30.0 | 30 | 3 |
| OTHER | 0 | 0.0 | 0 | 4 |
| PERSISTENCE | 30 | 30.0 | 30 | 4 |
| PRIVILEGE_ESCALATION | 30 | 30.0 | 30 | 4 |
| RECONNAISSANCE | 10 | 10.0 | 10 | 4 |

---

## Task 7 — Hybrid vs Rule-Only Analysis

| Metric | Value |
| :--- | ---: |
| Gemini Invocations | 0 / 42 (0.0%) |
| Rule-Only Accuracy | 1.0000 |
| Hybrid Accuracy | 1.0000 |
| Changed Predictions | 0 |

No classification changes observed between rule-only and hybrid predictions.

---

## Task 8 — Classification Latency

| Stage | Avg (ms) | Min (ms) | Max (ms) |
| :--- | ---: | ---: | ---: |
| Rule Classifier (100 reps) | 0.0213 | 0.0162 | 0.0718 |
| Hybrid Pipeline (100 reps) | 268.9498 | 178.716 | 393.2029 |
| Gemini API (eval runs) | N/A (Gemini not invoked) | N/A | N/A |

> **Note**: Latency measurements are indicative of local development performance.
> Gemini API latency depends on network and API load. Production-grade performance
> claims are not made from these measurements.

---

## Limitations

1. **Dataset size**: 42 test cases is appropriate for coverage demonstration but insufficient
   for statistical significance in a production threat detection context.
2. **Synthetic events**: Test cases are constructed NormalizedEvent objects with typical
   Cowrie field values. While they mirror real telemetry structure, they are not raw Cowrie JSON.
3. **Stage correlation**: Attack stage classification is derived from intent rule matches,
   not an independent model. Stage accuracy is therefore not fully independent of intent accuracy.
4. **Gemini variability**: Gemini responses are probabilistic. The Gemini latency and
   classification may vary between runs. Temperature=0.1 is set to minimize variability.
5. **Isolated environment**: All testing was conducted in an isolated local honeypot.
   No external systems were targeted.
6. **Risk weight subjectivity**: INTENT_BASE_WEIGHTS are project-defined constants and
   have not been empirically calibrated against real-world threat data.

---

## Generated Files

| File | Description |
| :--- | :--- |
| `evaluation_dataset.csv` | 42 labelled test cases with expected intent and stage |
| `evaluation_results.csv` | Per-case prediction, confidence, risk, source, and correctness |
| `metrics.json` | All aggregate metrics, per-class metrics, risk stats, and latency |
| `confusion_matrix.png` | Intent confusion matrix heatmap |
| `intent_distribution.png` | Ground truth vs predicted intent bar chart |
| `risk_distribution.png` | Risk score histogram with severity tier overlays |
| `latency_results.csv` | Classification latency measurements |
| `evaluation_report.md` | This document |