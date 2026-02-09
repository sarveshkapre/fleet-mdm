# Changelog

## Unreleased (2026-02-09)
- Add deterministic evidence `manifest.json` generation with per-artifact SHA256 and bundle fingerprinting.
- Add `fleetmdm evidence verify` to validate evidence integrity and optional HMAC signatures.
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
