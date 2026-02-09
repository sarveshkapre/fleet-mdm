# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P2 - More agent-side exporter examples (macOS: FileVault, OS update settings; Linux: disk encryption, kernel version) plus schema validation guidance.
- [ ] P2 - Reporting/scaling UX: add `report` filters (`--policy`, `--device`) to reduce noise at scale.
- [ ] P2 - Drift UX: add `drift --device` filter and include policy names in drift output.
- [ ] P2 - SARIF quality: optionally emit per-device failures (with a cap) and include richer SARIF rule metadata (descriptions, help URIs).
- [ ] P3 - Evidence packs: optionally include bounded `history` excerpts in evidence bundles for audit trails.
- [ ] P3 - `fleetmdm doctor` enhancements: optional `--integrity-check` and `--vacuum` guidance/automation.
- [ ] P3 - Config file support (for default `--db`, redaction defaults, evidence output path).
- [ ] P3 - Optional read-only web dashboard for inventory + compliance + evidence verification status.

## Implemented
- [x] 2026-02-09 - SQLite performance hardening: additional indexes for history/results query paths and `fleetmdm doctor` (DB stats + health signals). Evidence: `src/fleetmdm/store.py`, `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Added `fleetmdm report --format sarif` for code-scanning/compliance pipeline integration. Evidence: `src/fleetmdm/report.py`, `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Added `history` and `drift` filters (`--since` and `drift --policy`) for scale and noise reduction. Evidence: `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `tests/test_store.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Inventory ingest correctness: normalize `last_seen`, dedupe per payload by `device_id`, and prevent stale ingests from overwriting newer device state. Evidence: `src/fleetmdm/store.py`, `src/fleetmdm/inventory.py`, `src/fleetmdm/cli.py`, `tests/test_store.py`, `tests/test_inventory.py`.
- [x] 2026-02-09 - Added `fleetmdm report --format junit` (JUnit XML stdout) for pipeline ingestion. Evidence: `src/fleetmdm/report.py`, `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Evidence packs: redact policy `raw_yaml` in `strict` and strip comment-only lines in `minimal`. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - CLI reliability: `fleetmdm policy list` now initializes schema (`init_db`) on fresh DB paths. Evidence: `src/fleetmdm/cli.py`.
- [x] 2026-02-09 - Evidence signing key lifecycle metadata: keyring manifest (`keyring.json`), `fleetmdm evidence key list`, and `fleetmdm evidence key revoke` plus verify lifecycle checks (`signed_at`, activation/revocation windows). Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, smoke run.
- [x] 2026-02-09 - Added `fleetmdm evidence verify --output <file>` (JSON) for CI/audit pipelines. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Docs alignment: refreshed next improvements and roadmap to reflect shipped work. Evidence: `docs/PROJECT.md`, `docs/ROADMAP.md`, `docs/CHANGELOG.md`, `README.md`.
- [x] 2026-02-09 - Fixed CI secret scanning by replacing `gitleaks-action@v2` (license-gated) with pinned gitleaks CLI install + checksum verification. Evidence: `.github/workflows/ci.yml`.
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
- Treat `last_seen` as a monotonic freshness guard: normalization + stale-ingest skipping prevents accidental rollbacks when inventory is ingested out-of-order.
- `--since` and drift filters are cheap, high-value scale features: they keep history/drift usable once you have frequent runs.
- SARIF output makes FleetMDM results first-class in code-scanning/compliance pipelines without forcing a hosted service.
- A lightweight `doctor` command reduces operational friction (DB size, counts, pragmas, index visibility) and makes troubleshooting repeatable.

## Notes
- This file is maintained by the autonomous clone loop.
