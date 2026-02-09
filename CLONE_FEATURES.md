# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P1 - Add key lifecycle metadata for evidence signing (key activation dates, revocation, and keyring manifests).
- [ ] P2 - Add `fleetmdm evidence verify --output <file>` for CI/audit pipelines that want an artifact instead of stdout.
- [ ] P2 - Extend evidence redaction controls beyond inventory facts (for example, policy YAML `raw_yaml` redaction / stripping comments).
- [ ] P3 - Optional read-only web dashboard for inventory + compliance + evidence verification status.

## Implemented
- [x] 2026-02-09 - Tracked repo-wide `AGENTS.md` contract and refreshed session task tracker. Evidence: `AGENTS.md`, `CLONE_FEATURES.md`.
- [x] 2026-02-09 - Evidence signing key rotation workflow: add `fleetmdm evidence keygen` and `evidence verify --keyring-dir` (key-ID selection). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Machine-readable evidence verification report output: `fleetmdm evidence verify --format json`. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, smoke run.
- [x] 2026-02-09 - Evidence export facts redaction config (`--redact-config` allowlist/denylist). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Updated `docs/PROJECT.md` improvement list to reflect shipped roadmap. Evidence: `docs/PROJECT.md`.
- [x] 2026-02-09 - CI/tooling parity fix: `Makefile` now falls back to `python3` when `.venv` is absent and CI uses `make setup`. Evidence: `Makefile`, `.github/workflows/ci.yml`.
- [x] 2026-02-09 - Security gate fixes: removed `assert` control flow in CLI and refactored Bandit-flagged SQL query construction. Evidence: `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `make security`.
- [x] 2026-02-09 - Fresh DB reliability: `fleetmdm script list` now initializes DB schema. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`.
- [x] 2026-02-09 - Added SOC-style evidence export command. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Added evidence integrity manifest with per-artifact SHA256 + bundle fingerprint and deterministic artifact serialization. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, smoke run.
- [x] 2026-02-09 - Added `fleetmdm evidence verify` plus optional HMAC signing (`--signing-key-file`, `signature.json`). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, smoke run.
- [x] 2026-02-09 - Added evidence redaction profiles (`none|minimal|strict`) for device IDs and serials. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Enforced deterministic DB ordering for policies/devices/scripts/results/history paths. Evidence: `src/fleetmdm/store.py`, `make check`.
- [x] 2026-02-09 - Expanded CLI coverage for evidence export/verify tamper detection and profile behavior. Evidence: `tests/test_cli.py`, `make check`.
- [x] 2026-02-09 - Added session memory/incident docs (`PROJECT_MEMORY.md`, `INCIDENTS.md`) aligned with cycle evidence. Evidence: `PROJECT_MEMORY.md`, `INCIDENTS.md`.
- [x] 2026-02-09 - Regression coverage expanded for history filters and tag-assignment query behavior. Evidence: `tests/test_store.py`, `make check`.
- [x] 2026-02-09 - Policy evaluation context improved to include core device fields alongside facts (fixes seeded `os_version` checks). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, CLI smoke run.
- [x] 2026-02-09 - Documentation aligned with behavior changes and roadmap/changelog updates. Evidence: `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`.

## Insights
- CI failures were caused by environment mismatch (`make` assumed `.venv` while workflow installed into system Python); keeping one setup path removes this class of failure.
- Bandit was failing on both real and heuristic findings; explicit control-flow and static-query patterns keep security gate meaningful without broad suppressions.
- Seeded/demo workflows are a high-signal smoke test and caught a real evaluation-context gap that unit tests previously missed.
- Evidence packs are significantly more audit-ready with manifest hashing, optional signatures, and a verify command, but key lifecycle management remains the next trust gap.
- Deterministic ordering across DB reads materially improves CI snapshot stability and audit diff readability.
- Machine-readable CLI output should bypass rich rendering (`typer.echo`) to avoid line-wrapping that can corrupt long JSON strings.

## Notes
- This file is maintained by the autonomous clone loop.
