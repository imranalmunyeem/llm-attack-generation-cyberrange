PYTHON ?= python
VENV ?= .venv

ifeq ($(OS),Windows_NT)
VENV_PYTHON := $(VENV)/Scripts/python.exe
else
VENV_PYTHON := $(VENV)/bin/python
endif
ifeq ($(wildcard $(VENV_PYTHON)),)
VENV_PYTHON := $(PYTHON)
endif

.PHONY: env smoke pre-push-check scaleup-plan scaleup-small scaleup-full stats soc-sensitivity otrf-normalize sigma-replay-sample sigma-replay sigma-replay-intervals multimodel-plan multimodel-small multimodel-exact-size multimodel-expanded-plan multimodel-table real-baselines attack-version-robustness external-realism-validation leakage-audit corpus-diversity non-llm-baseline rs-weight-sensitivity statistical-hardening hardening-registry figure-export number-consistency supplemental-robustness annotation-prepare annotation-analyze reproducibility-ci reproduce qa paper-hardening

env:
	@$(PYTHON) scripts/create_env.py
	@$(VENV_PYTHON) -m pip install --upgrade pip
	@$(VENV_PYTHON) -m pip install -r requirements.lock

smoke:
	@$(VENV_PYTHON) tests/smoke_pipeline.py

pre-push-check:
	@bash scripts/pre_push_check.sh

scaleup-plan:
	@$(VENV_PYTHON) scaleup/corpus_scaleup.py --n 5000 --dry-run

scaleup-small:
	@$(VENV_PYTHON) scaleup/corpus_scaleup.py --n 20 --run --out data/generated/scaleup

scaleup-full:
	@$(VENV_PYTHON) scaleup/parallel_scaleup.py --n 5000 --shards 5 --run --out data/generated/scaleup --release-url "$$ADVERSIM_RELEASE_URL"

stats:
	@$(VENV_PYTHON) analysis/stats.py

soc-sensitivity:
	@$(VENV_PYTHON) analysis/soc_sensitivity.py

otrf-normalize:
	@$(VENV_PYTHON) detection/otrf_normalize.py --manifest data/raw_logs/phase4_source/otrf_selected/manifest.json --out data/raw_logs/sigma_replay_events.jsonl --summary data/raw_logs/sigma_replay_events_manifest.json

sigma-replay-sample:
	@$(VENV_PYTHON) detection/sigma_replay.py --rules tests/fixtures/sigma_replay/rules --events tests/fixtures/sigma_replay/events.jsonl --out results/sigma_measured_sample.json

sigma-replay:
	@$(VENV_PYTHON) detection/sigma_replay.py --rules data/generated/sigma_rules --events data/raw_logs/sigma_replay_events.jsonl --out results/sigma_measured.json

sigma-replay-intervals:
	@$(VENV_PYTHON) analysis/sigma_replay_intervals.py

multimodel-plan:
	@$(VENV_PYTHON) analysis/multimodel.py --dry-run

multimodel-small:
	@$(VENV_PYTHON) analysis/multimodel.py --run --n 48 --models gpt-4o-mini gpt-4.1-mini

multimodel-exact-size:
	@$(VENV_PYTHON) analysis/multimodel.py --run --n 150 --models gpt-4o-mini gpt-4.1-mini

multimodel-expanded-plan:
	@$(VENV_PYTHON) analysis/multimodel.py --dry-run --n 300 --models gpt-4o-mini gpt-4.1-mini o4-mini

multimodel-table:
	@$(VENV_PYTHON) analysis/multimodel_table.py

real-baselines:
	@$(VENV_PYTHON) baselines/real_baselines.py

attack-version-robustness:
	@$(VENV_PYTHON) analysis/attack_version_robustness.py

external-realism-validation:
	@$(VENV_PYTHON) analysis/external_realism_validation.py

leakage-audit:
	@$(VENV_PYTHON) analysis/leakage_audit.py

corpus-diversity:
	@$(VENV_PYTHON) analysis/corpus_diversity.py

non-llm-baseline:
	@$(VENV_PYTHON) analysis/non_llm_baseline.py

rs-weight-sensitivity:
	@$(VENV_PYTHON) analysis/rs_weight_sensitivity.py

statistical-hardening: sigma-replay-intervals
	@$(VENV_PYTHON) analysis/statistical_hardening.py

hardening-registry:
	@$(VENV_PYTHON) analysis/update_hardening_registry.py

figure-export:
	@$(VENV_PYTHON) visualization/build_architecture_figure.py
	@$(VENV_PYTHON) visualization/export_ieee_figures.py

number-consistency:
	@$(VENV_PYTHON) scripts/number_consistency_lint.py

paper-hardening: figure-export multimodel-table corpus-diversity non-llm-baseline rs-weight-sensitivity sigma-replay-intervals leakage-audit statistical-hardening hardening-registry number-consistency

supplemental-robustness: attack-version-robustness external-realism-validation leakage-audit
	@$(VENV_PYTHON) analysis/preregistered_blind_eval.py

annotation-prepare:
	@$(VENV_PYTHON) annotation/harness.py prepare --n 150

annotation-analyze:
	@$(VENV_PYTHON) annotation/harness.py analyze

reproducibility-ci:
	@$(VENV_PYTHON) scripts/reproducibility_ci.py

reproduce: reproducibility-ci

qa: reproducibility-ci pre-push-check
