# SavannaPay AICS-112 submission package

Name: Asim Shayan Khan. Prepared 30 September 2026.

This package contains a tested classroom SOAR application, synthetic datasets, preserved exercise evidence and final submission documents. All adapters are dry-run. The declaration contains the student-provided name, ID and typed signature. Final student review and the live or recorded demonstration remain to be confirmed.

## Read first

- submission/SavannaPay_Incident_Report.docx
- submission/SavannaPay_Model_Card.docx
- submission/SavannaPay_Playbook.json
- submission/SavannaPay_Test_and_Metrics_Report.md
- submission/SavannaPay_Demonstration_Guide.md
- submission/SavannaPay_Individual_Declaration.docx
- submission/evidence_manifest.csv

The declaration includes the student-provided ID and typed signature, with the duplicated reflection corrected. Confirm that the course accepts a typed signature and verify the LMS naming convention before submitting. Earlier documents in output/ are historical evidence. The submission/ documents describe the final implementation.

## Run

Use Python 3.11 or later. Core application and tests use the standard library; no pip installation is needed to run them.

```bash
python -m unittest discover -s tests -v
python app.py
```

Open http://127.0.0.1:8112. Both training and capstone data are installed in lab_data/. The final suite contains 29 tests. Run only one application process against a runtime directory.

For Ollama install and start the local service, obtain qwen3:4b, and set environment variables before starting the application:

```bash
AICS112_AI_PROVIDER=ollama AICS112_OLLAMA_MODEL=qwen3:4b python app.py
```

Without these settings the app uses the offline baseline. Ollama failures return fallback advice with provider_error. Preserved successful and fallback evidence is under output/lab4_ai/.

## CLI reproduction

```bash
python run_pipeline.py --dataset lab_data/training --output output/reproduced_training
python evaluate.py --incidents output/reproduced_training/incidents.json --truth lab_data/training/ground_truth.csv
python run_pipeline.py --dataset lab_data/capstone --output output/reproduced_capstone
```

Do not overwrite retained evidence. Browser incident IDs include dataset and run ID. Standalone CLI IDs remain SOAR-NNNN. Use event IDs and entity names to compare runs.

## Behavior and limits

The final browser API validates audit history before append or replay, uses unique run IDs, and reuses identical decisions without appending. Approval names are not authenticated and approvals do not expire. A repeated identical request from a different analyst is rejected as a conflict. Old incident IDs are rejected after a new run. The planned action list is not updated when a separate decision is recorded; inspect the audit panel.

The pipeline replaces its runtime incidents and action log on rerun. Preserve runs separately. AI recommendations still require review. No production adapters, multi-process coordination or atomic whole-pipeline publication are provided. The separate CLI instructor simulation token is not production authorization.

## Evidence and integrity

output/ preserves supplied historical evidence including intentional tampered copies; their names identify negative-test artifacts. Do not treat those copies as valid original chains. Final API evidence is under output/final_fixes/api_check_20260929T193822603056Z/.

submission/evidence_manifest.csv lists hashes of packaged files except the manifest itself. Original uploaded file bytes are preserved unless explicitly identified as updated documentation. The original README is retained at submission/README_original.md. The source application code is unchanged from the final review ZIP.
