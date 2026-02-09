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
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip -q install -e /Users/sarvesh/code/fleet-mdm
  fleetmdm init --db fleet.db
  fleetmdm seed --db fleet.db
  fleetmdm check --device mac-001 --db fleet.db --format json >/dev/null
  mkdir keys
  fleetmdm evidence keygen --keyring-dir keys >/dev/null
  keyfile=$(ls keys/*.key | head -n1)
  cat > redact.yml <<'YAML'
  facts_allowlist:
    - disk.encrypted
    - cpu.cores
  facts_denylist:
    - cpu.cores
  YAML
  fleetmdm evidence export --db fleet.db --output evidence --signing-key-file "$keyfile" --redact-profile strict --redact-config redact.yml >/dev/null
  fleetmdm evidence verify evidence --keyring-dir keys >/dev/null
  fleetmdm evidence verify evidence --keyring-dir keys --format json | python -c 'import json,sys; r=json.load(sys.stdin); assert r["ok"] is True and r["signature"]["verified"] is True'
  ```
- Commit:
  `943b662` (feature + tests), `a5c7f63` (docs + trackers), `791b218` (CI gitleaks fix).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - FleetDM: export formats and reporting expectations (CSV/JSON). https://fleetdm.com/docs/using-fleet/fleetctl-cli#export
  - Chef InSpec: machine-readable reporters (JSON/JUnit) as baseline for compliance tooling. https://docs.chef.io/inspec/reporters/
  - OpenSCAP: standardized assessment result formats (ARF) as an audit pipeline reference point. https://www.open-scap.org/tools/openscap-base/
  - Note: One CI failure in this cycle was caused by `gitleaks-action@v2` enforcing a license key; the workflow was updated to install and run pinned OSS gitleaks instead. (trusted: local diff + GitHub CI follow-up)

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
