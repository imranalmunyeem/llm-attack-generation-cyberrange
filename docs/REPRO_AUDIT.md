# Phase 0 Reproducibility Audit

Date: 2026-06-16
Branch: phase0-repro-audit
Repository: existing local checkout, not recloned

## Summary

Phase 0 established an offline smoke path, pinned dependency lock file, and local pre-push gate. The repository can now run a no-API smoke test on a checked-in 20-scenario fixture:

```powershell
python scripts\create_env.py
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe tests\smoke_pipeline.py
bash scripts/pre_push_check.sh
```

GNU Make is not installed on this workstation, but the checked-in `Makefile` maps `make env` and `make smoke` to the same commands. The local machine also lacks Python 3.11; `scripts/create_env.py` therefore created `.venv` with Python 3.12.10 and emitted a warning. A fresh reviewer container should use Python 3.11.x.

No `paper/` directory or `.tex` files are present in this checkout, so Table XVI cannot be read directly from the manuscript. The mapping below uses the scripts named in the handover and README as the audit baseline.

## Environment

| Item | Status | Evidence |
|---|---|---|
| Python target | Partial | `requirements.lock` targets Python 3.11.x; local verification used Python 3.12.10 because 3.11 is unavailable. |
| Dependency lock | Done | `requirements.lock` pins existing requirements and adds missing imports used by checked-in scripts: `mitreattack-python`, `scipy`, `scikit-learn`, and `PyYAML`. |
| Embedding backend | Documented | `mutation_engine_v14.py` uses SentenceTransformer if installed, otherwise offline TF-IDF. `requirements.lock` intentionally does not add `sentence-transformers`, so the reproducible default is TF-IDF. |
| ATT&CK bundle | Present with caveat | Tracked `data/journal_results/enterprise-attack.json` exists but is 36 MB. Untracked duplicate `data/journal_results/enterprise-attack-14.1.json` is ignored and must not be pushed. |
| API key | Safe | `.env` is ignored and not tracked (`git ls-files -- .env` returned empty). |

## Git Hygiene Gate

Implemented:

- `.gitignore` covers `.env`, key material, generated corpora, caches, raw SOC logs, and raw annotator data.
- `scripts/pre_push_check.sh` checks tracked plus untracked non-ignored files.
- The gate blocks files larger than 5 MB, with a hard limit of 25 MB.
- The historical tracked MITRE STIX bundle `data/journal_results/enterprise-attack.json` is explicitly grandfathered so the current repository can still pass; new duplicate STIX files are ignored/blocked.
- If `gitleaks` or `trufflehog` is installed, the script uses it. Otherwise it falls back to regex scanning for OpenAI keys, AWS access keys, and private-key blocks.
- `.git/hooks/pre-push` was installed from `scripts/pre_push_check.sh`.

Negative tests performed:

| Test | Result |
|---|---|
| Planted `phase0_large_test.bin` at 6,291,456 bytes | Blocked: above 5 MB soft limit. Artifact removed. |
| Planted `phase0_fake_secret.txt` with fake OpenAI key | Blocked: secret-like value detected. Artifact removed. |

## Smoke Test

Implemented:

- `tests/fixtures/mini_corpus.json`: 20 defensive scenario-metadata records.
- `tests/smoke_pipeline.py`: offline smoke harness that:
  - loads the fixture,
  - validates all technique IDs against the local ATT&CK STIX bundle,
  - runs `core.metrics_engine.analyze_dataset`,
  - runs `core.paper_analytics.run_paper_analysis` in a temp directory to avoid modifying checked-in figures,
  - generates Sigma rule skeletons into a temp directory.

Verified:

```text
smoke ok: fixture metrics, v14 validation, paper analytics, sigma generation
```

The smoke uses UTF-8 stdout/stderr because existing CLI scripts print Unicode arrows, which fail under the default Windows cp1252 console when run directly.

## Script Mapping And Status

| Paper/README script name | Actual path in checkout | Runs locally? | Produces numbers/artifacts | Notes |
|---|---|---:|---|---|
| `journal_experiments.py` | Missing | No | Intended Tables IV-XIV and figures | README references it, but it is absent. Closest current script is `run_paper_analysis.py`, which runs a smaller analytics subset. |
| `run_paper_analysis.py` | `run_paper_analysis.py` | Yes via smoke | `data/paper_analytics_report.json`, distribution figures | Hardcodes output under `data/`; smoke runs it in a temp cwd to avoid dirtying tracked PNGs. |
| `run_metrics.py` | `run_metrics.py` | Not in smoke | `data/research_metrics_report.json` | Hardcodes `dataset/dataset.jsonl`; no CLI dataset parameter. |
| `run_simulation.py` | `run_simulation.py` | Not in smoke | Console simulation for one random scenario | No deterministic seed or output file. |
| `instrumented_generator.py` | `instrumented_generator.py` | Needs API key | LLM first-attempt pass rate, token/cost statistics | Phase 0 does not call it. `.env` is ignored. |
| `diverse_generator.py` | `diverse_generator.py` | Needs API key | Diverse scenario corpus | Also present as `dataset/diverse/diverse_generator.py`; both should be reconciled later. |
| `mitre_attack_validator.py` | `mitre_attack_validator.py` | Yes via smoke | Active/deprecated/invalid technique classification | Used by smoke to validate fixture IDs. |
| `core_mitre_validation.py` | `core_mitre_validation.py` | Importable | Scenario validation helpers | Docstring references `core/mitre_validation.py`, but actual file is at repo root. |
| `mutation_engine_v14.py` | `mutation_engine_v14.py` | Importable if deps installed | Obfuscation/expansion mutation support | Default reproducible backend is TF-IDF unless `sentence-transformers` is separately installed. |
| `run_mutation_analysis.py` | `run_mutation_analysis.py` | Not run | Mutation metrics | Requires fuller audit in Phase 1 because its expected inputs/outputs are not documented in this checkout. |
| `attck_groups_validation.py` | `attck_groups_validation.py` | Data/internet dependent | External validation vs ATT&CK groups | Existing result file present. |
| `attck_groups_validation_v14.py` | `attck_groups_validation_v14.py` | Untracked existing file | External validation v14 variant | Present before Phase 0 work; preserved and not staged by this audit. |
| `sigma_rule_generator.py` | `sigma_rule_generator.py` | Yes via smoke | Sigma YAML skeletons and summary JSON | Direct CLI on Windows cp1252 fails on Unicode arrow output unless UTF-8 mode is enabled. |
| `annotation_sampler.py` | `annotation_sampler.py` | Partially | Annotation CSV/template/instructions | Direct CLI on Windows cp1252 fails on Unicode arrow output; also expects JSONL, not the smoke JSON fixture. |
| `analysis/build_results_registry.py` | Missing | No | Future `results/registry.json` | Phase 1 deliverable, not present now. |
| `analysis/audit_consistency.py` | Missing | No | Future macro/literal audit | Phase 1 deliverable, not present now. |
| `paper/generated_macros.tex` | Missing | No | Future LaTeX macros | Phase 1 deliverable; no `paper/` directory exists. |

## Paper Number Inventory

Because the manuscript source is absent, the audit cannot verify hard-coded `.tex` literals or Table XVI directly. The current status for headline claims is:

| Claim/key family | Status | Current evidence in checkout |
|---|---|---|
| Unique active ATT&CK v14 identifiers | Missing/recompute needed | README says 121 active v14; handover baseline says 145. No registry exists. |
| Base technique coverage | Missing/recompute needed | README says 60.2%; handover baseline says 48.8%. No registry exists. |
| First-attempt active-v14 rate | Needs API or cached run | README says 100% at n=240; handover baseline says 92.9% at n=1000. Must be regenerated or sourced from reliable cached telemetry. |
| Detection rates by environment | Partially reproducible | README contains table values; current simulation scripts are stochastic and not registry-backed. |
| Detection rates by attack type | Partially reproducible | README contains table values; no canonical registry or deterministic experiment runner exists. |
| Realism full-corpus mean and CV | Missing/recompute needed | README has CV value only; `journal_experiments.py` is absent. |
| Mutation metrics | Partially reproducible | `mutation_analysis_v14.json` exists and mutation scripts exist; no registry wiring. |
| External validation overlap/rho | Reproducible from cached result | `data/journal_results/attck_groups_validation.json` currently reports overlap 0.5582, weighted 0.5703, rho 0.1248, p 0.000138. |
| Graph complexity correlation | Missing/recompute needed | No registry or full journal experiment script present. |
| Cost per scenario | Needs API or cached telemetry | README says $0.000342; handover baseline says $0.000322. |
| Sigma rule count | Reproducible structurally | Smoke generated 20/20 rules from fixture; README claims 48 rules for paper corpus. |

## Gaps To Carry Into Phase 1

1. Add or reconstruct the missing `journal_experiments.py` functionality before building a number registry.
2. Decide which local ATT&CK STIX file is the official pinned v14.1 source. Do not commit the untracked duplicate `enterprise-attack-14.1.json` unless the large-file policy is changed and history risk is accepted.
3. Add deterministic seeds or output-capture around stochastic simulation metrics before treating detection/MTTD values as reproducible paper numbers.
4. Fix direct Windows CLI encoding in scripts that print Unicode arrows, or document `PYTHONUTF8=1` for Windows users.
5. Add manuscript source files before Phase 1/9 macro wiring and consistency auditing can be fully verified.

