# Combined Phase Closeout Audit

This audit records what is implemented in the closeout branch and what still
requires external action before the paper can honestly claim a completed run.

| Gap | Closeout implementation | Remaining external action |
|---|---|---|
| Phase 0.5 full scale-up | Added `make scaleup-full`, documented public sample/manifest/validation outputs, and retained `make scaleup-plan` for no-cost planning. | Run the paid API generation, upload the ignored full corpus to a citable release, and set or record `ADVERSIM_RELEASE_URL`. |
| Phase 5 exact-size replication | Added `make multimodel-exact-size` with `--n 150` per model. | Run the paid API replication before claiming exact-size Phase 5 results. |
| Phase 8 naming and Table XVI | Added `make reproduce`, `make submission-qa`, `docs/TABLE_XVI_REPRODUCIBILITY.md`, and `paper/table_xvi_reproducibility.tex`. | Insert the LaTeX table into the final journal template if using a separate source file. |
| Original-manuscript Phase 9 edits | Added `docs/MANUSCRIPT_SOURCE_CLOSEOUT.md` and updated the macro-wired manuscript scaffold. | Provide the original manuscript source if edits must be applied to that exact file. |
| Phase 10 pre-submission QA | Added `docs/SUBMISSION_CHECKLIST.md` and `docs/ANTICIPATED_REVIEWERS.md`. | Complete the manual checks after the final PDF is built. |

The closeout intentionally does not fabricate full-scale or exact-size API
outputs. The paper should describe the currently tracked Phase 5 result as a
small replication until `make multimodel-exact-size` has been run and committed.
