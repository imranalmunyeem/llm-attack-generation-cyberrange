# Table XVI Reproducibility Map

This file materializes the manuscript's Table XVI so the reproducibility
statement is no longer only implicit in the handover notes. It separates
offline checks from API-dependent regeneration.

| Claim family | Command or script | Primary output | External input | Submission status |
|---|---|---|---|---|
| Repository environment | `make env` | `.venv/` installed from `requirements.lock` | Python 3.11 target | Ready |
| Offline smoke path | `make smoke` | Smoke-test console result | None | Ready |
| Registry and macros | `make registry` | `results/registry.json`, `paper/generated_macros.tex`, `results/number_audit.md` | Tracked aggregate files | Ready |
| Figure regeneration | `make figures` | `paper_assets/figures/`, `results/figure_manifest.json` | Tracked aggregate files | Ready |
| Full offline reproducibility | `make reproduce` | Registry, number audit, figures, smoke check | No API key or raw logs | Ready |
| Pre-submission QA | `make submission-qa` | Reproducibility CI plus pre-push checks | No API key or raw logs | Ready |
| Phase 0.5 full corpus scale-up | `make scaleup-full` | `data/generated/scaleup/`, `dataset/samples/scaleup_sample.jsonl`, `dataset/manifests/scaleup_MANIFEST.json`, `results/scaleup_validation.json` | OpenAI API key; optional `ADVERSIM_RELEASE_URL` after upload | Runnable; requires paid API run and release URL |
| Phase 5 exact-size replication | `make multimodel-exact-size` | `data/generated/multimodel/`, `results/multimodel.json`, `results/multimodel_audit.md` | OpenAI API key | Runnable; requires paid API run |
| Phase 4 Sigma replay | `make sigma-replay` | `results/sigma_measured.json` | Labelled event dataset under `data/raw_logs/` | Runnable when logs are provided |
| Real public baselines | `make real-baselines` | `results/real_baselines.json`, audit note | Tracked/public metadata | Ready |
| Cross-version and external validity | `make supplemental-robustness` | ATT&CK robustness, preregistered blind-eval, external realism outputs | Tracked/public inputs | Ready |
| Human realism validation | `make annotation-analyze` | `results/human_validation.json`, `results/human_validation_audit.md`, figure | Anonymized reviewer ratings | Ready with provided ratings |

For the paper, use the LaTeX version in `paper/table_xvi_reproducibility.tex`.
The table intentionally avoids claiming that API-dependent full regeneration was
performed locally unless the corresponding output files and release URL exist.
