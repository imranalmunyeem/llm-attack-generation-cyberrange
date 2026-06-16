# Phase 3 SOC Simulation Artifact Audit

## Scope

This analysis treats detection, MTTD, and convergence as simulation outputs, not empirical measurements.
It sweeps the Bernoulli harness parameters and compares flat/stage detectability against a non-flat ATT&CK metadata proxy.

## Invariance Summary

- `environment_detection`: `parameter_sensitive`
- `attack_type_detection`: `parameter_sensitive`
- `difficulty_detection`: `parameter_sensitive`
- `stage_count_detection`: `parameter_sensitive`
- `stage_count_tautology`: `model_artifact`

## Finding Tags

- `environment_ordering`: `parameter_sensitive` -- Report only invariant pairwise orderings; avoid claiming a universal environment ranking unless the full ranking is invariant.
- `attack_type_ordering`: `parameter_sensitive` -- Treat attack-type detection rankings as simulation-harness behavior unless preserved under all detectability assumptions.
- `longer_chains_easier_to_detect`: `model_artifact` -- State this is expected analytically from the independent per-stage Bernoulli model; the contribution is magnitude/sensitivity, not discovery of the trend.
- `mttd_improvement_or_convergence`: `model_artifact` -- Frame Eq. 10 style convergence as harness stability/illustrative adaptation, not empirical analyst maturation.

## Required Paper Reframe

- Avoid words like measured/observed for simulated detection or MTTD until Phase 4 replay exists.
- Present longer-chain detection as an analytic consequence of independent per-stage detection.
- Report parameter-sensitive orderings as sensitivity results, not empirical findings.
- Treat feedback-loop convergence as harness stability, not proof of analyst maturation.
