# Anticipated Reviewer Questions and Responses

| Reviewer concern | Concise response | Evidence to cite |
|---|---|---|
| "Are these scenarios real incidents?" | No. The paper frames AdverSim as a defensive cyber-range scenario generator with validation layers, not as a replacement for real incident data. | `paper/manuscript_draft.tex`, `paper/validity_ethics_reproducibility.tex` |
| "Is `R(S)` just author-defined realism?" | `R(S)` is treated as a structural quality-control score. Human ratings show it is not a substitute for human realism judgment, which is why the paper reports human validation separately. | `results/human_validation.json`, `results/human_validation_audit.md`, `docs/PAPER_VALIDITY_ETHICS_REPRODUCIBILITY.md` |
| "Do detection results depend on simulator assumptions?" | The paper includes SOC-simulation sensitivity analysis and empirical Sigma replay grounding where labelled logs are available. | `results/soc_invariance.json`, `results/sigma_measured.json`, `paper_assets/figures/sigma_replay_coverage.png` |
| "Are baselines constructed by the authors?" | The main comparison now includes public metadata baselines from CALDERA Stockpile and Atomic Red Team, with limitations stated. | `results/real_baselines.json`, `results/real_baselines_audit.md` |
| "Does the validation generalize beyond one model?" | The repository now includes an exact-size 150-scenario-per-model replication for two OpenAI models, using the same validate-and-requery loop. | `analysis/multimodel.py`, `results/multimodel.json`, `results/multimodel_audit.md` |
| "Are claims reproducible without API keys?" | Aggregate checks, figures, macros, and smoke tests are reproducible offline with `make reproduce`; fresh full generation is explicitly API-dependent. | `docs/TABLE_XVI_REPRODUCIBILITY.md`, `scripts/reproducibility_ci.py` |
| "Is this dual-use?" | The artifact is scoped to defensive metadata and evaluation. It excludes payloads, live targets, malware execution, Atomic execution, and CALDERA agents. | `docs/PAPER_VALIDITY_ETHICS_REPRODUCIBILITY.md`, `paper/validity_ethics_reproducibility.tex` |
| "Where are raw human ratings and logs?" | Raw reviewer sheets, identities, and raw logs are excluded from git. The submission should include anonymized aggregates and a data-access statement. | `docs/SUBMISSION_CHECKLIST.md`, `.gitignore` |
| "Can Table XVI be regenerated?" | Table XVI is now represented as both Markdown and LaTeX, and the offline command is `make reproduce`. | `docs/TABLE_XVI_REPRODUCIBILITY.md`, `paper/table_xvi_reproducibility.tex` |
