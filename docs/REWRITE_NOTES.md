# Phase 9 Rewrite Notes

The original submitted manuscript source was not present in this checkout, so
the mechanical rewrite was implemented in the macro-wired scaffold rather than
inside the unavailable source file.

## Files Changed Or Added

- `paper/manuscript_draft.tex`
- `paper/generated_macros.tex`
- `paper/methods_algorithms.tex`
- `paper/validity_ethics_reproducibility.tex`
- `paper/table_xvi_reproducibility.tex`
- `docs/MANUSCRIPT_SOURCE_CLOSEOUT.md`

## Implemented Prose Fixes In The Scaffold

- Replaced overbroad realism language with an evidence-separated framing:
  ATT&CK validity, external grounding, real baselines, Sigma replay,
  multi-model replication, and human ratings are reported separately.
- Removed the impossible "78,000+" style claim by sourcing ATT&CK counts from
  `paper/generated_macros.tex`.
- Removed the spurious detection-rate wording by avoiding hand-typed headline
  detection literals in the scaffold.
- Framed `R(S)` as structural quality control, not as a substitute for human
  realism judgment.
- Added Table XVI through `paper/table_xvi_reproducibility.tex`.
- Tightened the dual-use statement around defensive metadata only.

## Items Requiring The Original Manuscript Source

These exact-source edits remain blocked until the original `.tex` or Word file
is provided:

- Delete leftover authoring instructions from the submitted abstract.
- Rewrite the exact submitted conclusion text containing garbled phrases.
- Rewrite the exact submitted Future Work prompt-injection and CALDERA
  paragraphs.
- Fix mangled bibliography entries and verify final DOI/URL formatting.
- Complete author biographies in the journal template.
- Shorten the final submitted title if the journal source still contains the
  duplicated adjective.

Use `docs/MANUSCRIPT_SOURCE_CLOSEOUT.md` as the transfer checklist when that
source file becomes available.
