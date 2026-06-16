# Pre-Submission QA Checklist

Use this checklist before sending the paper or artifact package to reviewers.

## Automated Checks

| Check | Command | Status |
|---|---|---|
| Rebuild registry, macros, figures, manifest, and smoke pipeline | `make reproduce` | Ready |
| Run the repository pre-push checks after reproducibility CI | `make submission-qa` | Ready |
| Audit manuscript numbers against the registry | `.\.venv\Scripts\python.exe analysis\audit_consistency.py --strict-paper` | Ready |
| Rebuild paper figures only | `make figures` | Ready |
| Plan full corpus scale-up without API calls | `make scaleup-plan` | Ready |
| Run full Phase 0.5 scale-up | `make scaleup-full` | Requires paid API run |
| Run exact-size Phase 5 replication | `make multimodel-exact-size` | Requires paid API run |

## Manual Paper Checks

- Confirm the final manuscript uses `paper/generated_macros.tex` or the same
  macro values copied from it.
- Confirm Table XVI appears in the final manuscript and matches
  `docs/TABLE_XVI_REPRODUCIBILITY.md`.
- Confirm the abstract and conclusion do not claim that synthetic scenarios are
  equivalent to real incidents.
- Confirm the Phase 7 wording says human ratings de-bias `R(S)` rather than
  validate `R(S)` as a substitute for human judgment.
- Confirm all dual-use and safety statements say the released corpus contains
  defensive metadata only, without payload code, live targets, malware, or
  executable adversary steps.
- Confirm `.env`, raw human rating sheets, reviewer identities, raw logs, and
  ignored full corpora are absent from the submission package.
- Confirm the paper lists the exact ATT&CK snapshot, model names, sample sizes,
  and release URL for any full API-generated corpus that is claimed.

## Blockers To Clear Before Claiming Full Regeneration

- Phase 0.5 full scale-up requires running `make scaleup-full` and uploading
  the ignored full corpus to a citable release. Set `ADVERSIM_RELEASE_URL` before
  the run if the URL is already known, or rerun the manifest step after upload.
- Phase 5 exact-size replication requires running `make multimodel-exact-size`.
  The currently tracked result is a smaller replication and must not be
  described as the exact-size run.
- The original manuscript source is absent. Source-specific edits to the
  original abstract, conclusion, references, and bios require that file.
