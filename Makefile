VENV?=.venv
PY?=$(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup dev test lint typecheck build security check release

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -U pip
	$(VENV)/bin/python -m pip install -e ".[dev]"

dev:
	$(PY) -m fleetmdm.cli --help

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests

typecheck:
	$(PY) -m pyright

build:
	$(PY) -m build

security:
	$(PY) -m pip_audit
	$(PY) -m bandit -q -r src

check: lint typecheck test build

release: check
	@echo "Release gate passed."
