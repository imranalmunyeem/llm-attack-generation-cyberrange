PYTHON ?= python
VENV ?= .venv

ifeq ($(OS),Windows_NT)
VENV_PYTHON := $(VENV)/Scripts/python.exe
else
VENV_PYTHON := $(VENV)/bin/python
endif

.PHONY: env smoke pre-push-check scaleup-plan scaleup-small registry audit-consistency stats soc-sensitivity sigma-replay-sample sigma-replay

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

registry:
	@$(VENV_PYTHON) analysis/build_results_registry.py

audit-consistency:
	@$(VENV_PYTHON) analysis/audit_consistency.py

stats:
	@$(VENV_PYTHON) analysis/stats.py

soc-sensitivity:
	@$(VENV_PYTHON) analysis/soc_sensitivity.py

sigma-replay-sample:
	@$(VENV_PYTHON) detection/sigma_replay.py --rules tests/fixtures/sigma_replay/rules --events tests/fixtures/sigma_replay/events.jsonl --out results/sigma_measured_sample.json

sigma-replay:
	@$(VENV_PYTHON) detection/sigma_replay.py --rules data/journal_results/sigma_rules --events data/raw_logs/sigma_replay_events.jsonl --out results/sigma_measured.json
