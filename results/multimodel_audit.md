# Phase 5 Multi-LLM Generalization Audit

Phase 5 reuses `scaleup/corpus_scaleup.py` so each model uses the same
balanced plan, defensive metadata-only prompt, active ATT&CK v14 validation,
and validate-and-requery loop.

Full generated corpora and per-model logs are written under `data/generated/`
and are intentionally not committed.

## Results

| Model | n accepted | First-attempt active-v14 | Unique active IDs | Base techniques | Cost/scenario |
|---|---:|---:|---:|---:|---:|
| gpt-4o-mini | 48 | 93.8% [0.8316, 0.9785] | 35 | 29 | $0.000445 |
| gpt-4.1-mini | 47 | 97.9% [0.891, 0.9963] | 81 | 57 | $0.000526 |

Union unique active v14 IDs across completed models: 90.

## Paper Framing

Report this as a small stratified cross-model replication. The central
claim is method robustness: the active-v14 validation and requery loop is
model-agnostic. Do not claim that a 48-scenario replication fully
characterizes any model family.
