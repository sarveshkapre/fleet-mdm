VENV?=.venv
PY?=$(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)

.PHONY: setup dev smoke test lint typecheck build security check release

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/python -m pip install -U pip
	$(VENV)/bin/python -m pip install -e ".[dev]"

dev:
	$(PY) -m fleetmdm --help

smoke:
	@tmpdir=$$(mktemp -d); \
	db="$$tmpdir/fleet.db"; \
	$(PY) -m fleetmdm init --db "$$db" >/dev/null; \
	$(PY) -m fleetmdm seed --db "$$db" >/dev/null; \
	$(PY) -m fleetmdm report --db "$$db" --format json --sort-by failed --top 1 >/dev/null; \
	$(PY) -m fleetmdm check --db "$$db" --device mac-001 --format json >/dev/null; \
	$(PY) -m fleetmdm check --db "$$db" --device mac-001 --format json >/dev/null; \
	$(PY) -m fleetmdm history --db "$$db" --format json --since 2000-01-01T00:00:00Z >/dev/null; \
	$(PY) -m fleetmdm drift --db "$$db" --format json --since 2000-01-01T00:00:00Z >/dev/null; \
	rm -rf "$$tmpdir"

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
