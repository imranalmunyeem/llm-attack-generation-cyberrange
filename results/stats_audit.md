# Phase 2 Statistical Rigor Audit

## External Validation

- Observed transition corroboration: 0.558
- Null transition corroboration mean: 0.417 with 95% band [0.304957, 0.526967]
- Empirical permutation p for transition corroboration: 0.003996
- Observed Spearman rho: 0.125; rho^2 = 0.016

Interpretation: the external-validation signal should be framed as small and directional.
The transition-corroboration rate is the more interpretable headline; rho is supporting evidence.

## Multiple Testing

All available p-values in `results/stats_table.json` include Holm-Bonferroni adjusted values.
Rows without raw p-values are marked as aggregate-only, documented-only, or missing.

## Remaining Gaps

- `journal_experiments.py` and `all_results.json` are absent, so Table XI cannot yet be fully regenerated.
- Graph-complexity correlation is still missing and must be recomputed when the journal experiment source is restored.
- Mutation CIs need per-scenario outputs; current mutation JSON contains only aggregates.
