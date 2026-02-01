VENV?=.venv
PY=$(VENV)/bin/python

setup:
	python3 -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[dev]"

dev:
	$(PY) -m fleetmdm --help

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
