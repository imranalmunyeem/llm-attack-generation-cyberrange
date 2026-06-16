# Phase 5 Multi-LLM Generalization Audit

Phase 5 reuses `scaleup/corpus_scaleup.py` so each model uses the same
balanced plan, defensive metadata-only prompt, active ATT&CK v14 validation,
and validate-and-requery loop.

Full generated corpora and per-model logs are written under `data/generated/`
and are intentionally not committed.

## Results

| Model | n accepted | First-attempt active-v14 | Unique active IDs | Base techniques | Cost/scenario |
|---|---:|---:|---:|---:|---:|
| gpt-4o-mini | 150 | 96.7% [0.9243, 0.9857] | 58 | 48 | $0.000423 |
| gpt-4.1-mini | 150 | 94.7% [0.8983, 0.9727] | 135 | 83 | $0.000521 |

Union unique active v14 IDs across completed models: 151.

## Paper Framing

Report this as an exact-size stratified cross-model replication when
`replication_n_per_model` is 150 or higher. The central
claim is method robustness: the active-v14 validation and requery loop is
model-agnostic. Do not overclaim that this fully characterizes any
model family.
