# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1 - Add integrity manifest/signing for `fleetmdm evidence export` bundles to improve audit trust.
- [ ] P1 - Add configurable redaction profiles for evidence export (for serials/device IDs).
- [ ] P2 - Add deterministic ordering/snapshots for table outputs to improve golden-test stability.

## Implemented
- [x] 2026-02-09 - CI/tooling parity fix: `Makefile` now falls back to `python3` when `.venv` is absent and CI uses `make setup`. Evidence: `Makefile`, `.github/workflows/ci.yml`.
- [x] 2026-02-09 - Security gate fixes: removed `assert` control flow in CLI and refactored Bandit-flagged SQL query construction. Evidence: `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `make security`.
- [x] 2026-02-09 - Fresh DB reliability: `fleetmdm script list` now initializes DB schema. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`.
- [x] 2026-02-09 - Added SOC-style evidence export command. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Regression coverage expanded for history filters and tag-assignment query behavior. Evidence: `tests/test_store.py`, `make check`.
- [x] 2026-02-09 - Policy evaluation context improved to include core device fields alongside facts (fixes seeded `os_version` checks). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, CLI smoke run.
- [x] 2026-02-09 - Documentation aligned with behavior changes and roadmap/changelog updates. Evidence: `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`.

## Insights
- CI failures were caused by environment mismatch (`make` assumed `.venv` while workflow installed into system Python); keeping one setup path removes this class of failure.
- Bandit was failing on both real and heuristic findings; explicit control-flow and static-query patterns keep security gate meaningful without broad suppressions.
- Seeded/demo workflows are a high-signal smoke test and caught a real evaluation-context gap that unit tests previously missed.
- Evidence export is now viable for audits, but integrity/signing and redaction are the next high-impact improvements.

## Notes
- This file is maintained by the autonomous clone loop.
