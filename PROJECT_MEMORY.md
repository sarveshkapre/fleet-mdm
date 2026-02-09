# Project Memory

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
  Pending in-session commit on `main`.
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Follow-ups:
  Add key rotation/key lifecycle strategy and machine-readable verify reports for external audit pipelines.
