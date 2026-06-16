# Phase 1 Number Audit

## Registry Status

- `cached_reproducible`: 49
- `documented_not_regenerated`: 7
- `missing`: 2

## Fixed / Canonicalized Values

| Item | Before / conflicting source | Registry value | Evidence |
|---|---|---|---|
| Unique active ATT&CK IDs | README says 121 active / handover flags 78,000+ manuscript artifact | 145 | validation_report_v14.json + full_dataset_v14clean.jsonl |
| Base technique coverage | README says 60.2% (121/201) | 48.8% (98/201) | computed against active v14 base techniques |
| First-attempt active-v14 rate | README hallucination report says 100% for n=240 | 92.9% for the original 1,000-scenario corpus before remediation | validation_report_v14.json |
| External validation | README says 53.6% / rho 0.122 | 55.8% unweighted, 57.0% weighted, rho 0.1248 | data/journal_results/attck_groups_validation.json |
| Cost per scenario | README prose/table also contains $0.34 per 1,000 and $0.000342 | $0.000322 | data/journal_results/hallucination_report.json |

## Still Missing Or Not Regenerated

- `det.env.cloud`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `det.env.enterprise`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `det.env.healthcare`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `det.env.ics`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `graphcomplexity.pearson_r`: missing -- No journal_experiments.py/all_results.json source exists in this checkout
- `graphcomplexity.pearson_r2`: missing -- No journal_experiments.py/all_results.json source exists in this checkout
- `realism.cv_mean`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `realism.cv_sd`: documented_not_regenerated -- journal_experiments.py is absent in this checkout
- `sigma.rules_generated`: documented_not_regenerated -- README value; smoke validates generator structure but not this exact full-corpus count

## Manuscript Wiring Status

`paper/manuscript_draft.tex` is a macro-wired manuscript scaffold.
Headline registry values should be cited through `paper/generated_macros.tex`.
Run `analysis/audit_consistency.py --strict-paper` to check manuscript
entry points for hard-coded registry literals.
