PYTHON ?= python
VENV ?= .venv

ifeq ($(OS),Windows_NT)
VENV_PYTHON := $(VENV)/Scripts/python.exe
else
VENV_PYTHON := $(VENV)/bin/python
endif

.PHONY: env smoke pre-push-check scaleup-plan scaleup-small

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
