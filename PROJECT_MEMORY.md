# Project Memory

## 2026-02-09 - Cycle 1 - Evidence Key Rotation + Machine-Readable Verify
- Decision:
  Add an evidence signing key lifecycle starter kit: `evidence keygen`, key-ID-aware `evidence verify --keyring-dir`, machine-readable verification reports (`--format json`), and configurable inventory facts redaction (`--redact-config`).
- Why:
  Evidence bundles were tamper-evident, but operational key rotation and pipeline ingestion were still awkward; adding a keyring-based verify path and JSON reports closes the biggest audit automation gap without expanding scope beyond local-first CLI.
- Evidence:
  `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`, `docs/PROJECT.md`.
- Verification:
  `make setup` (pass), `make check` (pass), `make security` (pass).
  Smoke: create DB, seed, check, `evidence keygen`, signed+strict+redact-config `evidence export`, `evidence verify --keyring-dir`, `evidence verify --format json` parse/assert (pass).
- Commit:
  `943b662` (feature + tests).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - FleetDM: export formats and reporting expectations (CSV/JSON). https://fleetdm.com/docs/using-fleet/fleetctl-cli#export
  - Chef InSpec: machine-readable reporters (JSON/JUnit) as baseline for compliance tooling. https://docs.chef.io/inspec/reporters/
  - OpenSCAP: standardized assessment result formats (ARF) as an audit pipeline reference point. https://www.open-scap.org/tools/openscap-base/

## 2026-02-09 - Cycle 2 - Evidence Trust Hardening
- Decision:
  Implement deterministic evidence manifests, optional HMAC signing, bundle verification, and export redaction profiles in the CLI.
- Why:
  The highest-impact remaining gap was audit trust: bundles were exportable but not tamper-evident or privacy-aware.
- Evidence:
  `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`.
- Verification:
  `make check`, `make security`, CLI smoke path with signed strict-redacted bundle export + verify.
- Commit:
  `55c70d5`, `9643e7d`.
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Follow-ups:
  Add key rotation/key lifecycle strategy and machine-readable verify reports for external audit pipelines.
