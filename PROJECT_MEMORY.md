# Project Memory

## 2026-02-09 - Cycle 4 - Scaling UX + SARIF + Doctor
- Recent Decisions:
  Add scaling filters (`history --since`, `drift --since`, `drift --policy`), add `report --format sarif`,
  and ship `fleetmdm doctor` plus additional SQLite indexes for history/results query paths.
- Why:
  These are the highest leverage production-readiness gaps for a local-first compliance tool: reduce noise
  as runs grow, integrate with CI/code-scanning pipelines, and give operators fast DB visibility without
  needing ad-hoc SQLite poking.
- Gap map (bounded, based on local repo + untrusted market scan):
  - Missing: SARIF output (now shipped), operational DB introspection (`doctor`, now shipped).
  - Weak: Scale ergonomics for frequent runs (history/drift noise; now improved via `--since`/filters).
  - Parity: JUnit/JSON machine-readable outputs (already present; SARIF improves parity for code-scanning).
  - Differentiator: Local-first evidence packs with manifests/signatures + verify workflow (already shipped).
- Prioritization (impact/effort/fit/risk/confidence):
  Picked `--since`/filters, SARIF output, and `doctor`/indexes as high-impact/low-risk CLI improvements that
  compound across every user workflow; deferred dashboard/exporter expansions as higher-effort.
- Evidence:
  `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `src/fleetmdm/report.py`, `tests/test_cli.py`,
  `tests/test_store.py`, `README.md`, `docs/CHANGELOG.md`, `docs/PROJECT.md`, `docs/ROADMAP.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass)
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip -q install -U pip
  python -m pip -q install -e /Users/sarvesh/code/fleet-mdm
  fleetmdm init --db fleet.db
  fleetmdm seed --db fleet.db
  fleetmdm check --device mac-001 --db fleet.db --format json >/dev/null
  fleetmdm check --device mac-001 --db fleet.db --format json >/dev/null
  fleetmdm history --db fleet.db --format json --since 2000-01-01T00:00:00Z >/dev/null
  fleetmdm drift --db fleet.db --format json --since 2000-01-01T00:00:00Z >/dev/null
  fleetmdm drift --db fleet.db --format json --since 2000-01-01T00:00:00Z --policy disk-encryption >/dev/null
  fleetmdm report --db fleet.db --format sarif > report.sarif
  fleetmdm doctor --db fleet.db --format json >/dev/null
  ```
- Mistakes And Fixes:
  - Root cause: built a dynamic SQL query string for `list_compliance_history`, which triggered Bandit B608.
  - Fix: revert to static query variants and keep parameters separate from SQL text.
  - Prevention: avoid string-built SQL in security-gated code paths; prefer explicit query branches.
  - Root cause: introduced mixed tab/space indentation inside a multiline SQL schema string, failing ruff (E101).
  - Fix: rewrite the schema string without tabs and keep indentation consistent.
  - Prevention: avoid tabs in multiline strings; run `make check` before committing.
- Commits:
  `f47e683` (history/drift filters), `f2750fc` (SARIF report), `8f48f3c` (doctor + indexes + docs).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - GitHub code scanning expects SARIF uploads and documents the SARIF schema/usage. https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
  - Chef InSpec sets baseline expectations for compliance tooling reporters (JSON/JUnit). https://docs.chef.io/inspec/reporters/
  - FleetDM emphasizes automation-first, CLI-driven workflows with exportable outputs. https://fleetdm.com/docs/using-fleet/fleetctl-cli#export

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

## 2026-02-09 - Cycle 2 - Evidence Key Lifecycle Metadata + Verify Output Artifacts
- Recent Decisions:
  Add a keyring manifest (`keyring.json`) with basic key lifecycle metadata (created/activated/revoked), add `fleetmdm evidence key list/revoke`, and extend `fleetmdm evidence verify` with `--output` for pipeline-friendly JSON artifacts plus lifecycle validation (using `signature.json` `signed_at`).
- Why:
  Evidence bundles were verifiable cryptographically, but audit workflows still needed operational key tracking (revocation state) and file-based outputs that CI/audit systems can ingest and store as artifacts.
- Evidence:
  `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`, `docs/PROJECT.md`.
- Verification Evidence:
  `make check` (pass), `make security` (pass).
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
  fleetmdm evidence keygen --keyring-dir keys >/dev/null
  fleetmdm evidence key list --keyring-dir keys --format json >/dev/null
  keyfile=$(python -c 'import json; import pathlib; d=json.loads(pathlib.Path("keys/keyring.json").read_text()); print("keys/"+d["keys"][0]["filename"])')
  fleetmdm evidence export --db fleet.db --output evidence --signing-key-file "$keyfile" --redact-profile strict >/dev/null
  fleetmdm evidence verify evidence --keyring-dir keys --format json --output verify.json
  python -c 'import json; d=json.load(open("verify.json")); assert d["ok"] is True and d["signature"]["verified"] is True'
  ```
- Mistakes And Fixes:
  - Root cause: introduced mixed tabs/spaces during a large edit to `src/fleetmdm/cli.py`, breaking syntax and linting.
  - Prevention: keep edits localized and always run `make check` before committing/pushing.
- Commit:
  `57612e1`.
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - NIST OSCAL: standardized compliance/evidence models that many audit pipelines expect to integrate with. https://pages.nist.gov/OSCAL/

## 2026-02-09 - Cycle 3 - Compliance Pipeline Outputs + Ingest Freshness Guard
- Recent Decisions:
  Add `fleetmdm report --format junit`, extend evidence export redaction to policy `raw_yaml` (redacted in `--redact-profile strict`, comment-only lines stripped in `minimal`), and harden inventory ingest by normalizing `last_seen` and skipping stale updates (plus dedupe per payload by `device_id`).
- Why:
  JUnit XML output makes it trivial to plug FleetMDM into CI/compliance gates, policy YAML redaction reduces the chance of leaking sensitive policy content into evidence bundles, and monotonic `last_seen` prevents accidental state rollbacks when inventory is ingested out of order.
- Evidence:
  `src/fleetmdm/report.py`, `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `src/fleetmdm/inventory.py`, `tests/test_cli.py`, `tests/test_store.py`, `tests/test_inventory.py`, `README.md`, `docs/CHANGELOG.md`, `CLONE_FEATURES.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass; Bandit clean, pip-audit clean)
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  cd "$tmpdir"
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip -q install -e /Users/sarvesh/code/fleet-mdm

  fleetmdm init --db fleet1.db
  fleetmdm seed --db fleet1.db
  fleetmdm report --db fleet1.db --format junit > report.xml

  cat > policy.yaml <<'YAML'
  # comment line should be stripped
  id: disk-encryption
  name: Disk Encryption Enabled
  checks:
    - key: disk.encrypted
      op: eq
      value: true
  YAML
  fleetmdm policy add policy.yaml --db fleet1.db
  fleetmdm evidence export --db fleet1.db --output evidence-min --redact-profile minimal
  fleetmdm evidence export --db fleet1.db --output evidence-strict --redact-profile strict

  fleetmdm init --db fleet2.db
  cat > newer.json <<'JSON'
  {
    "device_id": "mac-999",
    "hostname": "studio-9",
    "os": "macos",
    "os_version": "14.4",
    "serial": "C02XYZ999",
    "last_seen": "2026-02-02T00:00:00Z",
    "facts": {"disk": {"encrypted": true}}
  }
  JSON
  cat > older.json <<'JSON'
  {
    "device_id": "mac-999",
    "hostname": "studio-9",
    "os": "macos",
    "os_version": "14.4",
    "serial": "C02XYZ999",
    "last_seen": "2026-02-01T00:00:00Z",
    "facts": {"disk": {"encrypted": false}}
  }
  JSON
  fleetmdm ingest newer.json --db fleet2.db
  fleetmdm ingest older.json --db fleet2.db
  fleetmdm export --db fleet2.db --output inv.json
  ```
- Mistakes And Fixes:
  - Root cause: added a JUnit XML renderer using `xml.etree.ElementTree`, which Bandit flags (B405) by default even when used only for XML generation.
  - Fix: add a targeted `# nosec B405` with justification in `src/fleetmdm/report.py`.
  - Prevention: run `make security` before pushing, especially after introducing new imports.
- Commits:
  `230ded7` (cycle 3 task list), `edf64e5` (report junit), `7d94615` (policy YAML redaction), `4e89d37` (ingest normalization + stale guard), `3851144` (Bandit suppression for safe XML generation).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - Chef InSpec supports standard JUnit XML reporting via its `junit2` reporter (baseline CI ingestion expectation). https://docs.chef.io/inspec/5.23/configure/reporters/
  - Kandji positions reporting for compliance and audit readiness as a first-class workflow (UX expectation: fast, low-friction reporting). https://www.kandji.io/features/prism/
  - FleetDM emphasizes automation-first, CLI-driven workflows (baseline expectation: exportable/machine-readable outputs). https://fleetdm.com/docs/using-fleet/configuration-files
