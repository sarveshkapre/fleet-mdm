# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration

## Candidate Features To Do
- [ ] P2 - CI reliability: pin Python patch version in workflow matrix and add periodic dependency update policy doc. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- [ ] P2 - CLI UX: normalize invalid `--format` handling across commands with consistent exit code/text. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- [ ] P2 - Policy quality gate: add `fleetmdm policy lint` for schema + semantic checks without DB mutation. Score: impact 4, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- [ ] P2 - Assignment UX: add `policy assignments --unmatched-tags` to detect stale tag assignments. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- [ ] P2 - Security docs: add explicit threat model and trust boundaries for local-first deployment. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- [ ] P2 - Reliability: add explicit error taxonomy (`code`, `message`) for JSON-mode failures. Score: impact 4, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- [ ] P3 - `fleetmdm doctor` enhancements: optional `--integrity-check` and `--vacuum` guidance/automation. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 4.
- [ ] P3 - Config file support for default `--db`, report defaults, and evidence output path. Score: impact 3, effort 4, fit 4, differentiation 2, risk 2, confidence 3.
- [ ] P3 - Performance: add microbench for report/drift with synthetic 10k-row history and index tuning follow-ups. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- [ ] P3 - Security: redact high-risk fact keys by default (`serial`, `uuid`, hardware IDs) in strict evidence profile metadata docs. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- [ ] P3 - Exporter parity: add Linux secure-boot fact collection and schema guidance in examples. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- [ ] P3 - Exporter parity: add macOS firewall facts and bootstrap token posture fields in examples. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- [ ] P3 - Optional read-only web dashboard for inventory/compliance/evidence verify status. Score: impact 3, effort 5, fit 3, differentiation 3, risk 3, confidence 2.
- [ ] P3 - Packaging: provide Homebrew/Nix install docs with checksum-based release artifact verification. Score: impact 2, effort 3, fit 3, differentiation 1, risk 1, confidence 3.
- [ ] P3 - Ops UX: add `fleetmdm report --output` for direct file artifact creation without shell redirects. Score: impact 3, effort 2, fit 3, differentiation 1, risk 1, confidence 4.
- [ ] P3 - Ops UX: add `fleetmdm history --latest-run` shortcut for rapid post-check troubleshooting. Score: impact 2, effort 2, fit 3, differentiation 1, risk 1, confidence 4.
- [ ] P3 - Docs quality: split long command recipes into `docs/` pages and keep README within two-screen quickstart. Score: impact 2, effort 2, fit 4, differentiation 1, risk 1, confidence 4.

## Implemented
- [x] 2026-02-12 - SARIF parity upgrade: enrich SARIF rule metadata (`helpUri`, `fullDescription`) and add `report --sarif-max-failures-per-policy` for bounded failed-device samples. Evidence: `src/fleetmdm/report.py`, `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-12 - Evidence parity upgrade: add `evidence export --history-limit N` with optional `history.json` excerpts and strict redaction consistency for history device IDs. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-12 - Report UX for scale: add `fleetmdm report --sort-by name|failed|passed` and `--top N` for deterministic ranking/slicing. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-12 - CLI reliability hardening: validate malformed `--since` in `history` and `drift` with clear error messaging and exit code `2`. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-12 - Developer verification UX: add deterministic `make smoke` workflow (`init`/`seed`/`report`/`check`/`history`/`drift`) and document it. Evidence: `Makefile`, `README.md`, `docs/PROJECT.md`.
- [x] 2026-02-11 - Report UX for scale: add `fleetmdm report --only-assigned` to force assignment-scoped report evaluation even when no assignments exist. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-11 - Drift UX: add `fleetmdm drift --include-new-missing` and surface `change_type` (`changed|new|missing`) in drift outputs. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-10 - Release hygiene: add `fleetmdm.__main__` so `python -m fleetmdm` works; ensure `python -m fleetmdm.cli` also runs; update `make dev` and add a smoke test. Evidence: `src/fleetmdm/__main__.py`, `src/fleetmdm/cli.py`, `Makefile`, `tests/test_cli.py`.
- [x] 2026-02-10 - Report UX: add `fleetmdm report --only-failing` and `--only-skipped` for scale/noise reduction. Evidence: `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`.
- [x] 2026-02-10 - CSV export hardening: use proper CSV writers and mitigate spreadsheet formula injection across CSV outputs (`check`/`report`/`history`/`drift`). Evidence: `src/fleetmdm/csvutil.py`, `src/fleetmdm/cli.py`, `src/fleetmdm/report.py`, `tests/test_cli.py`.
- [x] 2026-02-10 - CI security gate: suppress Bandit B405 false positive on safe JUnit XML generation import. Evidence: `src/fleetmdm/report.py`, `make security`.
- [x] 2026-02-09 - Exporters: extend macOS exporter with OS update preference facts and Linux exporter with kernel + disk encryption heuristics; add schema validation guidance. Evidence: `examples/exporters/macos_inventory.py`, `examples/exporters/linux_inventory.py`, `examples/exporters/README.md`.
- [x] 2026-02-09 - Reporting/scaling UX: add `report --policy` and `report --device` filters. Evidence: `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Drift UX: add `drift --device` filter and include `policy_name` in drift output (json/csv/table). Evidence: `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `tests/test_cli.py`, `README.md`.
- [x] 2026-02-09 - Tooling: fix `make dev` to run `python -m fleetmdm.cli` (package has no `__main__`). Evidence: `Makefile`.
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
- Assignment semantics are safest when explicit: `report --only-assigned` prevents accidental “evaluate everything” behavior in large fleets that are migrating to assignment-based scoping.
- Drift deltas are more actionable when membership changes are first-class (`new`/`missing`), not only status flips; this avoids blind spots when policies/devices appear or disappear between runs.
- CI failures were caused by environment mismatch (`make` assumed `.venv` while workflow installed into system Python); keeping one setup path removes this class of failure.
- Bandit was failing on both real and heuristic findings; explicit control-flow and static-query patterns keep security gate meaningful without broad suppressions.
- Seeded/demo workflows are a high-signal smoke test and caught a real evaluation-context gap that unit tests previously missed.
- Evidence packs are significantly more audit-ready with manifest hashing, optional signatures, and a verify command, but key lifecycle management remains the next trust gap.
- Deterministic ordering across DB reads materially improves CI snapshot stability and audit diff readability.
- Machine-readable CLI output should bypass rich rendering (`typer.echo`) to avoid line-wrapping that can corrupt long JSON strings.
- Treat `last_seen` as a monotonic freshness guard: normalization + stale-ingest skipping prevents accidental rollbacks when inventory is ingested out-of-order.
- `--since` and drift filters are cheap, high-value scale features: they keep history/drift usable once you have frequent runs.
- Sorting plus `--top` is a low-effort, high-signal triage multiplier for large policy sets; it helps operators focus on worst failures first.
- Timestamp validation should fail fast in CLI surface area: returning a clear error message (instead of bubbling parser tracebacks) materially improves operator UX and automation reliability.
- SARIF output makes FleetMDM results first-class in code-scanning/compliance pipelines without forcing a hosted service.
- SARIF consumers benefit from metadata depth (`helpUri`, richer descriptions) and bounded device samples; this keeps scanner output actionable without unbounded payload growth.
- A lightweight `doctor` command reduces operational friction (DB size, counts, pragmas, index visibility) and makes troubleshooting repeatable.
- Optional bounded evidence history excerpts reduce auditor context switches while preserving artifact-size control.
- Market scan signals that exportable audit artifacts and scheduled exports are baseline expectations; CLI filters + machine-readable outputs are high leverage.
- CSV exports are a frequent audit artifact; protecting against spreadsheet formula injection is a cheap, high-signal hardening step (especially when inventory/policy strings are untrusted inputs).

## Notes
- This file is maintained by the autonomous clone loop.
