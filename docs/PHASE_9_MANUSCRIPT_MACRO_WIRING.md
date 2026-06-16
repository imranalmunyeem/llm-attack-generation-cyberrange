# Phase 9 Manuscript Rewrite and Macro Wiring

Phase 9 adds a paper presentation layer without changing the underlying
results. The repository did not contain a main manuscript source, so this phase
creates a macro-wired manuscript scaffold and extends the registry/macro system
to cover the newer validation phases.

## New Manuscript Entry Point

```text
paper/manuscript_draft.tex
```

The draft uses:

```tex
\input{generated_macros.tex}
```

Headline numbers should be referenced only through macros from
`paper/generated_macros.tex`. Avoid hard-coded values in the manuscript body.

## Regeneration Commands

```powershell
.\.venv\Scripts\python.exe analysis\build_results_registry.py
.\.venv\Scripts\python.exe analysis\audit_consistency.py --strict-paper
.\.venv\Scripts\python.exe scripts\reproducibility_ci.py
```

## CI Wiring

The reproducibility runner now:

- rebuilds `results/registry.json`
- rebuilds `paper/generated_macros.tex`
- rebuilds `results/number_audit.md`
- audits manuscript entry points for hard-coded registry literals
- regenerates figures and validates `results/figure_manifest.json`
- runs the offline smoke pipeline

The GitHub Actions drift check includes:

- `paper/generated_macros.tex`
- `paper_assets/figures/`
- `results/registry.json`
- `results/number_audit.md`
- `results/figure_manifest.json`

## Presentation Fix

The manuscript scaffold separates evidence streams:

- structural ATT&CK validity and coverage
- external transition validation
- real metadata baselines
- Sigma replay
- multi-model generalization
- human realism validation
- reproducibility and ethics

This keeps the paper from overclaiming that one metric proves realism.
