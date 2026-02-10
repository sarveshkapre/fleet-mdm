# Changelog

## Unreleased (2026-02-10)
- Add `fleetmdm report --only-failing` and `--only-skipped` for noise reduction at scale.
- Fix CI security gate: annotate safe ElementTree usage for JUnit generation so Bandit doesn’t fail on a non-parsing import.
- Add `fleetmdm report --policy` and `fleetmdm report --device` filters for scale/noise reduction.
- Add `fleetmdm drift --device` and include `policy_name` in drift outputs.
- Extend exporter examples: macOS now emits best-effort Software Update preference facts; Linux now emits kernel release + root encryption heuristics.
- Fix `make dev` to run `python -m fleetmdm.cli` (package has no `__main__`).
- Add `fleetmdm evidence keygen` to generate signing keys with stable key IDs.
- Add `keys/keyring.json` keyring manifests with key lifecycle metadata (created/activated/revoked) plus `fleetmdm evidence key list` and `fleetmdm evidence key revoke`.
- Add `--keyring-dir` to `fleetmdm evidence verify` to support signing key rotation via key-ID selection.
- Add `fleetmdm evidence verify --format json` to emit a machine-readable verification report.
- Add `fleetmdm evidence verify --output <file>` for CI/audit pipelines that want an artifact instead of stdout.
- Add `fleetmdm report --format junit` for JUnit XML compliance pipeline ingestion.
- Add `fleetmdm report --format sarif` for code-scanning/compliance pipeline ingestion.
- Extend evidence redaction to policies: redact `policies.json` `raw_yaml` in `--redact-profile strict` and strip comment-only lines in `minimal`.
- Normalize inventory `last_seen` timestamps and prevent stale ingests from overwriting newer device state.
- Add `--since` to `fleetmdm history` and `fleetmdm drift` plus `--policy` filter for `fleetmdm drift`.
- Add `fleetmdm doctor` and additional SQLite indexes for history/results query paths.
- Add `--redact-config` to `fleetmdm evidence export` for allowlist/denylist redaction of inventory `facts.*` fields.
- Add deterministic evidence `manifest.json` generation with per-artifact SHA256 and bundle fingerprinting.
- Add `fleetmdm evidence verify` to validate evidence integrity and optional HMAC signatures.
- Include `signed_at` timestamps in `signature.json` for key lifecycle validation.
- Add evidence export redaction profiles (`none`, `minimal`, `strict`) for device identifiers and serials.
- Add optional `--signing-key-file` support for HMAC-signed evidence manifests (`signature.json`).
- Improve deterministic ordering across policy/device/script/result DB read paths for stable exports and snapshots.
- Add `fleetmdm evidence export` to generate SOC-style evidence bundles (`metadata`, `inventory`, `policies`, `assignments`, `latest_run`, `drift`).
- Fix CI environment parity: `make` now works with or without a local `.venv`, and GitHub Actions uses `make setup`.
- Fix `fleetmdm script list` on fresh databases by ensuring schema initialization.
- Harden security gate by removing `assert`-based CLI control flow and refactoring SQL paths to satisfy Bandit.
- Evaluate policies against merged device + facts context so checks like `os_version` work without duplicating values in facts.

## 0.1.0
- Initial MVP: inventory ingest, policy validation, compliance checks, reporting, script catalog
- Add policy assignments: device + tag, plus `policy assignments` and `policy unassign`
- Add inventory schema export: `fleetmdm schema inventory`
- Add sample inventory exporters (macOS/Linux) under `examples/exporters/` and `fleetmdm inventory validate`
- Add compliance history recording + `fleetmdm history`
- Add compliance drift report: `fleetmdm drift`
- Add policy targets for OS/tags in YAML
