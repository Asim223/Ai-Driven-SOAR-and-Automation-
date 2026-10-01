# AICS-112 mini-SOAR project

This dependency-free Python project powers a real browser-based AI-SOAR Operations Console. Students turn synthetic SOC telemetry into correlated candidate incidents, explainable risk scores, AI-assisted summaries, approval-gated response plans, and tamper-evident audit records.

## Safety boundary

Every response action is a dry-run simulation. The project contains no production credentials and does not call real identity, endpoint, firewall, email, or cloud APIs.

## Quick start

1. Use Python 3.11 or later.
2. From this folder, run `python -m unittest discover -s tests -v`.
3. Complete the TODOs in `soar_lab/pipeline.py` following the Student Lab Manual.
4. Use the included `lab_data/training` evidence during Weeks 1–2.
5. On Week 3 Day 2, extract the separately released capstone dataset into `lab_data/capstone`; do not obtain it early.
6. Run `python app.py` and open `http://127.0.0.1:8112` to use the Operations Console.
7. Use the console to run evidence, inspect incidents, request AI analysis, approve/deny simulated containment and review the audit trail.
8. You can also run `python run_pipeline.py --dataset lab_data/training --output output/training` from the terminal.
9. Evaluate with `python evaluate.py --incidents output/training/incidents.json --truth lab_data/training/ground_truth.csv`.

## Required supervised local generative AI exercise

Students must connect the console to the free local Ollama API for the Week 2 AI exercise and submit comparison evidence. The offline explainable model remains a safe fallback for service-failure testing or an instructor-approved technical accommodation. Install Ollama, then run:

`ollama pull qwen3:4b`

Windows PowerShell:

`$env:AICS112_AI_PROVIDER="ollama"; $env:AICS112_OLLAMA_MODEL="qwen3:4b"; python app.py`

Linux/macOS:

`AICS112_AI_PROVIDER=ollama AICS112_OLLAMA_MODEL=qwen3:4b python app.py`

The application constrains the model to a JSON schema, validates next-step tokens against a fixed allowlist, treats evidence as untrusted text, and keeps every AI output advisory-only. If Ollama is unavailable or returns invalid output, the app visibly falls back to the offline model.

Expected initial state: three tests fail because Labs 2-4 are intentionally incomplete. Do not copy the instructor solution.
