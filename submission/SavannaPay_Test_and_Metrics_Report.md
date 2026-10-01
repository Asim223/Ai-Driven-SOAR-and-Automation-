# SavannaPay test and metrics report

Author: Asim Shayan Khan. Prepared 30 September 2026. All activity uses synthetic evidence and dry-run actions.

## Result

29 tests passed from the final package source. The uploaded final HTTP report records nine passing checks. The reviewer independently verified the saved final action and decision chains. Live Ollama was not rerun during packaging; its successful, timeout/fallback and injection responses are retained from Colab.

## Test coverage

| Area | Tests | Scope |
|---|---:|---|
| Starter pipeline | 7 | Normalization, enrichment, score, injection flag, severity bands, chain links |
| Extra normalization | 3 | Input preservation, missing ID, negative severity |
| Extra enrichment | 4 | Confidence boundary, preservation, string privilege, unknown defaults |
| Lab 6 safety | 2 | Low-confidence IOC rejection and unapproved critical containment |
| Standalone ledger | 2 | Persistent replay and denial |
| Capstone features | 4 | Event-specific severity and prevention context |
| Audit append | 3 | Preserve prior bytes, reject tampering and supplied hashes |
| Scoped decisions | 4 | Replay, fresh run IDs, conflict and tampered-history rejection |
| **Total** | **29** | See fresh_extraction_tests.txt |

The final API report checks simulated approval, replay identity, no duplicate append, denial, disjoint dataset IDs, stale request rejection, no stale append, dry-run actions and pending capstone containment. These nine checks are separate from the unit-test count. Evidence: ../output/final_fixes/api_check_20260929T193822603056Z/api_check_report.json.

## Training metrics

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 50 | 8 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 |
| 65 | 8 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 |
| 75 | 8 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 |
| 85 | 8 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 |

Evaluation is event-level: the incident prediction is assigned to each constituent event. Eight malicious events are one chain, not eight independent incidents. Twelve labeled training events do not support a broad accuracy claim. Threshold 65 remains provisional; these results cannot rank the four thresholds. Source: final_metrics.json, ../output/capstone_improvements/20260929T192120491065Z/training/incidents.json, ../lab_data/training/ground_truth.csv and ../evaluate.py.

## Capstone assessment

60 events form nine candidates: two critical, one high, six low. The primary suspected compromise concerns fatima.sani. The administrator candidate mixes failures and lockout with routine activity; the HR candidate records blocked/quarantined attachment activity. No capstone labels were used or requested. Capstone precision, recall and F1 are unavailable.

## Integrity tests and latency

Original saved chains verify. Changing a status causes a record-hash mismatch; recomputing that changed record alone breaks the next link. The append fix rejects altered existing history rather than silently rechaining it. Hash chains alone do not provide trusted timestamps, authorization or protection against complete chain rewriting. Sources: output/lab6_assurance audit_review files, tests/test_audit_append.py and app.py.

Ollama timings were 39.3 seconds for the successful comparison, 61.1 seconds for the injected incident, and 90.13 seconds for the timeout/fallback example. These are single observations. The HTTP named approval and denial occur in an automated test; their timestamps must not be presented as measured human approval latency. End-to-end analyst response latency was not measured.

## Limits and open work

- Single-process decision locking does not provide multi-process coordination.
- Pipeline outputs are rewritten in stages; concurrent reads or interruption can observe incomplete state.
- Decision records persist, but prior pipeline runs should be archived separately because runtime action logs are replaced on rerun.
- Roles, expiry, revocation and production recovery are not implemented.
- AI validation is partial; contradictory allowed recommendations can pass.
- STIX validity dates are not enforced. Low-confidence rejection is tested.
- Correlation uses rolling gaps and may over-group routine activity.
- CLI simulation approval token is an instructor exercise, not authenticated approval.

## Reproduction

From package root:

```bash
python -m unittest discover -s tests -v
python run_pipeline.py --dataset lab_data/training --output output/reproduced_training
python evaluate.py --incidents output/reproduced_training/incidents.json --truth lab_data/training/ground_truth.csv
python run_pipeline.py --dataset lab_data/capstone --output output/reproduced_capstone
```

The evaluator uses threshold 65. Other threshold results are retained in final_metrics.json. Preserve original evidence folders. Source requirements: AICS-112 Student Lab Manual, Lab 6, and Capstone Project and Submission Templates, Template E.
