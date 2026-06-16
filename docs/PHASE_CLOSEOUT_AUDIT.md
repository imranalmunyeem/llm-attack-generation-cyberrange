# Combined Phase Closeout Audit

This audit records what is implemented in the closeout branch and what still
requires external action before the paper can honestly claim a completed run.

| Gap | Closeout implementation | Remaining external action |
|---|---|---|
| Phase 0.5 full scale-up | Ran the 5,000-scenario paid API scale-up via `scaleup/parallel_scaleup.py`; committed only the sample, manifest, and validation summary. | Upload `data/generated/scaleup/adversim_scaleup_full.jsonl` to a citable release and record the URL in the manifest. |
| Phase 5 exact-size replication | Ran `make multimodel-exact-size` equivalent with `--n 150` for `gpt-4o-mini` and `gpt-4.1-mini`; updated `results/multimodel.json` and audit note. | None for local completion; avoid claiming non-OpenAI model generalization unless a third model is added. |
| Phase 8 naming and Table XVI | Added `make reproduce`, `make submission-qa`, `docs/TABLE_XVI_REPRODUCIBILITY.md`, and `paper/table_xvi_reproducibility.tex`. | Insert the LaTeX table into the final journal template if using a separate source file. |
| Original-manuscript Phase 9 edits | Added `docs/MANUSCRIPT_SOURCE_CLOSEOUT.md` and updated the macro-wired manuscript scaffold. | Provide the original manuscript source if edits must be applied to that exact file. |
| Phase 10 pre-submission QA | Added `docs/SUBMISSION_CHECKLIST.md` and `docs/ANTICIPATED_REVIEWERS.md`. | Complete the manual checks after the final PDF is built. |

The closeout now includes real full-scale and exact-size API outputs. The only
remaining Phase 0.5 external action is release upload/DOI assignment for the
ignored full corpus.
