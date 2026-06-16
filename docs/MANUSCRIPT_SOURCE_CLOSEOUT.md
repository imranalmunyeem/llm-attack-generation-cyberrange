# Original Manuscript Source Closeout

The original submitted manuscript source was not present in this checkout.
Because of that, the repository cannot directly edit the original abstract,
body text, references, or author biographies. The closeout implements the
paper-facing changes in a new macro-wired entry point instead:

- `paper/manuscript_draft.tex`
- `paper/generated_macros.tex`
- `paper/methods_algorithms.tex`
- `paper/validity_ethics_reproducibility.tex`
- `paper/table_xvi_reproducibility.tex`

## Implemented Presentation Fixes

- Headline numeric claims are pulled from `paper/generated_macros.tex`.
- The abstract frames AdverSim as a defensive cyber-range pipeline, not as a
  substitute for real incident data.
- The results section separates ATT&CK validity, external grounding, real
  baselines, Sigma replay, multi-model replication, and human realism.
- The human-validation result states that `R(S)` is a structural quality-control
  metric, not a complete human-realism proxy.
- The appendix includes system architecture, pseudocode, complexity, validity,
  ethics, artifact availability, and Table XVI reproducibility mapping.

## Manual Source-Specific Items Still Needed

If the original `.tex` or Word manuscript is later provided, copy these sections
into it and run `make reproduce` afterward:

- Replace old abstract claims with the macro-wired abstract from
  `paper/manuscript_draft.tex`.
- Replace any hard-coded headline numbers with macros from
  `paper/generated_macros.tex`.
- Insert `paper/table_xvi_reproducibility.tex` at the reproducibility table
  location.
- Replace overbroad realism language with the Phase 7 wording about `R(S)` and
  human judgment.
- Refresh references, author biographies, funding, conflicts, acknowledgments,
  and data-availability statements in the journal template.
