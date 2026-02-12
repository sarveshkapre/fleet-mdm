# Project Memory

## Historical Summary
- 2026-02-12T16:40:47Z: compacted memory from 501 lines. Full snapshot archived at /Users/sarvesh/code/fleet-mdm/.clone_memory_archive/PROJECT_MEMORY-20260212T164047Z.md

  - Environment issue: security/build commands require network-accessible dependency metadata or preinstalled backend packages not available in this sandbox.
  - Prevention rule: continue recording partial-gate outcomes explicitly and run full security/build in CI or network-enabled environment.
- What changed and why:
  - Added operator-focused report ranking controls and bounded outputs to improve triage speed.
  - Added early timestamp validation to improve reliability and clear UX for automation scripts.
  - Added an explicit smoke path to keep release-readiness checks repeatable.
- What remains next:
  - Highest pending parity features: SARIF metadata enrichment and bounded evidence history excerpts.
  - Reliability follow-up: unify error-code/message behavior across all command `--format` and input-validation paths.

## 2026-02-12 - Session Notes Checkpoint (Cycle 1, Session 2, pre-implementation)
- Goal:
  Ship the highest-impact pending M3 parity work by improving SARIF report fidelity and adding bounded history excerpts to evidence bundles.
- Success Criteria:
  - `report --format sarif` includes richer policy metadata and supports bounded failed-device detail output.
  - `evidence export` can emit optional bounded `history.json` excerpts.
  - Local verification gates pass (`make check`, `make security`, `make smoke`) plus targeted smoke paths for the new flags.
  - `PRODUCT_ROADMAP.md`, `CLONE_FEATURES.md`, and `README.md` stay aligned with behavior.
- Non-goals:
  - Optional dashboard work.
  - Config defaults file support.
  - Doctor integrity/vacuum automation.
- Planned Tasks (Locked):
  - Add SARIF rule metadata depth and per-policy failed-device cap support, with regression tests.
  - Add evidence export `--history-limit` with bounded excerpt artifact and redaction-consistent behavior, with tests.
  - Update docs/trackers and verification evidence.
- Product Phase Checkpoint:
  - Are we in a good product phase yet? `No`.
  - Highest-value missing parity features this session: SARIF metadata/depth and evidence history excerpts.
- Pending Features Review:
  - Still pending (from `PRODUCT_ROADMAP.md` + `CLONE_FEATURES.md`): doctor integrity guidance, config defaults, security default redaction hardening, exporter parity, performance benchmark, packaging docs, optional dashboard.
- Market scan (bounded, untrusted):
  - Intune compliance monitoring + drill-down workflows: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Intune export APIs for filtered reporting automation: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Kandji reporting/filter workflow reference: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
  - FleetDM compliance dashboard expectations: https://fleetdm.com/docs/using-fleet/mdm/compliance-dashboard
- Trust Label:
  `trusted` for local repo state and planned tasks, `untrusted` for external market references.

## 2026-02-12 - Cycle 1 - SARIF Metadata Depth + Evidence History Excerpts
- Recent Decisions:
  Ship the two highest-impact pending parity items together: (1) SARIF metadata depth + bounded per-policy failed-device context, and (2) optional bounded history excerpts in evidence exports.
- Why:
  SARIF scanners and compliance tooling need richer rule metadata and controlled detail payloads; auditors need recent history context inside evidence packs without exporting the full database.
- Gap map (bounded; local code + untrusted market scan):
  - Missing (before this cycle): SARIF metadata depth/per-device context cap; bounded evidence history excerpts.
  - Weak: doctor integrity/maintenance guidance and config defaults ergonomics.
  - Parity: report filtering/sorting, assignment-aware evaluation, machine-readable outputs, evidence verify/signing/key lifecycle.
  - Differentiator: local-first evidence trust pipeline (manifest/signature/verify) with optional history context.
- Evidence:
  `src/fleetmdm/report.py`, `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`, `docs/PROJECT.md`, `PRODUCT_ROADMAP.md`, `CLONE_FEATURES.md`.
- Verification Evidence:
  `make check` (fail: `build` step could not install `hatchling>=1.24.0` due offline DNS/network in sandbox)
  `make security` (fail: `pip_audit` attempted to access non-writable `~/.pip-audit-cache` path in sandbox)
  `.venv/bin/python -m bandit -q -r src` (pass)
  `.venv/bin/python -m pip_audit --cache-dir /tmp/pip-audit-cache` (fail: offline DNS resolution to `pypi.org`)
  `make smoke` (pass)
  `.venv/bin/python -m pytest tests/test_cli.py -k "sarif or evidence_export_history_excerpt"` (pass)
  Targeted smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  db="$tmpdir/fleet.db"
  .venv/bin/python -m fleetmdm seed --db "$db" >/dev/null
  cat > "$tmpdir/policy.yaml" <<'YAML'
  id: cpu-min
  name: CPU Minimum 64 Cores
  description: Require at least 64 CPU cores
  checks:
    - key: cpu.cores
      op: gte
      value: 64
  YAML
  .venv/bin/python -m fleetmdm policy add "$tmpdir/policy.yaml" --db "$db" >/dev/null
  .venv/bin/python -m fleetmdm report --db "$db" --format sarif --sarif-max-failures-per-policy 1 > "$tmpdir/report.sarif"
  .venv/bin/python -m fleetmdm check --db "$db" --device mac-001 >/dev/null
  .venv/bin/python -m fleetmdm check --db "$db" --device linux-001 >/dev/null
  .venv/bin/python -m fleetmdm evidence export --db "$db" --output "$tmpdir/evidence" --history-limit 2 --redact-profile strict >/dev/null
  .venv/bin/python -m fleetmdm evidence verify "$tmpdir/evidence" >/dev/null
  ```
- Mistakes And Fixes:
  - Environment constraint: `pip_audit` default cache path was not writable inside sandbox.
  - Remediation: run `pip_audit` with explicit writable cache dir (`--cache-dir /tmp/pip-audit-cache`) and record offline-network limitation separately.
- Commit:
  `a61da2c`.
- Confidence:
  High on feature behavior and tests; medium on full release gate due network-restricted build/security dependency resolution.
- Trust Label:
  `trusted` for local edits/tests/smoke, `untrusted` for external references.

## 2026-02-11 - Cycle 1 - Assignment-Scoped Reporting + Drift Membership Deltas
- Recent Decisions:
  Ship two roadmap items together: add `fleetmdm report --only-assigned` to force assignment-scoped report evaluation, and add `fleetmdm drift --include-new-missing` to include policy/device pairs present in only one of the compared runs.
- Why:
  Assignment scoping protects large fleets from accidentally evaluating all policies when rollout assignments are still being staged, and drift without membership deltas misses high-signal changes when policies/devices appear or disappear between runs.
- Gap map (bounded; local code + untrusted market scan):
  - Missing (before this cycle): forced assignment-scoped reporting, drift membership deltas.
  - Weak: SARIF metadata depth and per-device detail for failing policies.
  - Parity: machine-readable outputs (`json`, `junit`, `sarif`) and assignment-aware policy resolution.
  - Differentiator: local-first evidence export/verify pipeline with deterministic manifests and signing.
- Evidence:
  `src/fleetmdm/cli.py`, `tests/test_cli.py`, `README.md`, `docs/CHANGELOG.md`, `docs/ROADMAP.md`, `docs/PROJECT.md`, `CLONE_FEATURES.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass)
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  db="$tmpdir/fleet.db"
  .venv/bin/python -m fleetmdm init --db "$db" >/dev/null
  .venv/bin/python -m fleetmdm seed --db "$db" >/dev/null
  .venv/bin/python -m fleetmdm report --db "$db" --format json --only-assigned >/dev/null
  .venv/bin/python -m fleetmdm policy assign min-os-version --device mac-001 --db "$db" >/dev/null
  .venv/bin/python -m fleetmdm report --db "$db" --format json --only-assigned >/dev/null
  .venv/bin/python -m fleetmdm check --db "$db" --device mac-001 --format json >/dev/null
  .venv/bin/python -m fleetmdm check --db "$db" --device mac-001 --format json >/dev/null
  .venv/bin/python -m fleetmdm drift --db "$db" --format json --include-new-missing >/dev/null
  ```
  CI triage:
  `gh run view 21855372955 --log-failed` (pass; historical failure analyzed, root cause = Ruff import violations on old commit)
  `gh run view 21895431235 --json status,conclusion,url` (pass; `success` on pushed feature commit)
  Issue scan:
  `gh issue list --state open --limit 50 --json number,title,author,url,labels,createdAt,updatedAt` (pass; no open issues from `sarveshkapre`/trusted bots)
- Mistakes And Fixes:
  None this cycle.
- Commit:
  `df40621`.
- CI:
  GitHub Actions run `21895431235` (success).
- Confidence:
  High.
- Trust Label:
  `trusted` (local code/tests/CI), with external references below marked `untrusted`.
- Market scan (bounded, untrusted):
  - Intune treats compliance reporting as a primary workflow surface. https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Intune highlights monitoring devices without assigned compliance policy, reinforcing assignment-scoped visibility expectations. https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor-devices
  - FleetDM public API/docs emphasize automation-ready fleet/compliance workflows and structured outputs. https://fleetdm.com/docs/rest-api/rest-api
  - Jamf’s compliance positioning reinforces benchmark-oriented compliance visibility as expected MDM capability. https://www.jamf.com/resources/press-releases/jamf-compliance-benchmarks-help-organizations-manage-and-ensure-compliance-across-devices/

## 2026-02-10 - Cycle 2 - Python `-m` Entrypoint Parity
- Recent Decisions:
  Add `fleetmdm.__main__` and a `fleetmdm.cli:main` entrypoint so `python -m fleetmdm` and `python -m fleetmdm.cli` execute the CLI; update `make dev` to use `python -m fleetmdm --help`; add a small smoke test.
- Why:
  `python -m ...` module execution is a common local/CI smoke path and avoids relying on the console script wrapper.
  Previously `python -m fleetmdm.cli` was a no-op (module import only), which could mask broken smoke commands.
- Evidence:
  `src/fleetmdm/__main__.py`, `src/fleetmdm/cli.py`, `Makefile`, `tests/test_cli.py`, `docs/CHANGELOG.md`, `CLONE_FEATURES.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass)
  Smoke (pass):
  ```bash
  .venv/bin/python -m fleetmdm --help >/dev/null
  .venv/bin/python -m fleetmdm.cli --help >/dev/null
  ```
- Commit:
  `3381afe`.
- Confidence:
  High.
- Trust Label:
  `verified-local`.

## 2026-02-10 - Cycle 1 - Report Noise Filters + CSV Export Hardening
- Recent Decisions:
  Add `fleetmdm report --only-failing` and `--only-skipped` to reduce noise at scale, and harden CSV outputs by switching CLI CSV emitters to `csv.writer` plus basic spreadsheet formula injection protection.
- Why:
  Large fleet reporting needs first-order noise controls, and CSV exports are a common audit artifact where quoting and formula injection defenses prevent avoidable footguns.
- Gap map (bounded; based on local repo + untrusted market scan):
  - Missing: `report --only-assigned`, drift “new/missing rows”, optional dashboard.
  - Weak: CSV robustness/safety (now improved), scale-oriented report slicing (now improved).
  - Parity: machine-readable outputs (JSON/JUnit/SARIF) plus exportable summaries.
  - Differentiator: local-first evidence packs with manifests/signatures + verify workflow.
- Evidence:
  `src/fleetmdm/cli.py`, `src/fleetmdm/report.py`, `src/fleetmdm/csvutil.py`, `tests/test_cli.py`, `README.md`,
  `docs/CHANGELOG.md`, `docs/PROJECT.md`, `docs/ROADMAP.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass)
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  db="$tmpdir/fleet.db"
  .venv/bin/python -m fleetmdm.cli init --db "$db"
  .venv/bin/python -m fleetmdm.cli seed --db "$db"
  .venv/bin/python -m fleetmdm.cli check --db "$db" --device mac-001
  .venv/bin/python -m fleetmdm.cli report --db "$db" --format json --only-failing >/dev/null
  .venv/bin/python -m fleetmdm.cli report --db "$db" --format csv >/dev/null
  ```
- Commit:
  `6ec26aa`.
- CI:
  GitHub Actions runs `21855600070` (success) and `21855623374` (success).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - Microsoft Intune surfaces device compliance reporting and export as a baseline expectation for MDM operations. https://learn.microsoft.com/en-us/mem/intune/protect/compliance-reports
  - Jamf positions compliance benchmarking/reporting as a first-class workflow surface area. https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Compliance_Benchmarks.html
  - FleetDM’s docs emphasize automation-first inventory/compliance workflows and exportable outputs as table-stakes. https://fleetdm.com/docs
  - FleetDM’s handbook calls out CSV injection risks and mitigations, reinforcing the value of safe-by-default CSV emitters. https://fleetdm.com/handbook/company/security#csv-injection

## 2026-02-09 - Cycle 5 - Report/Drift Filters + Exporter Parity
- Recent Decisions:
  Add `report --policy/--device` filters, add `drift --device` and include `policy_name` in drift output, fix `make dev` to run the real CLI module, and enrich exporter examples (macOS Software Update preferences; Linux kernel + disk encryption heuristics).
- Why:
  Scale workflows need “reduce noise” knobs (`--policy`, `--device`) and drift needs to be readable without cross-referencing IDs.
  Exporters are the fastest path to usable real-world facts, and `make dev` should match docs and work on a fresh checkout.
- Evidence:
  `src/fleetmdm/cli.py`, `src/fleetmdm/store.py`, `tests/test_cli.py`, `README.md`, `Makefile`,
  `examples/exporters/macos_inventory.py`, `examples/exporters/linux_inventory.py`, `examples/exporters/README.md`,
  `docs/CHANGELOG.md`, `docs/PROJECT.md`, `docs/ROADMAP.md`.
- Verification Evidence:
  `make check` (pass)
  `make security` (pass; Bandit clean, pip-audit clean)
  Exporter validation (pass):
  ```bash
  tmpdir=$(mktemp -d)
  python3 examples/exporters/macos_inventory.py > "$tmpdir/device.json"
  fleetmdm inventory validate "$tmpdir/device.json"
  ```
  Smoke (pass):
  ```bash
  tmpdir=$(mktemp -d)
  db="$tmpdir/fleet.db"

  fleetmdm init --db "$db"
  fleetmdm ingest examples/device.json --db "$db"
  fleetmdm policy add examples/policy.yaml --db "$db"
  fleetmdm check --device mac-001 --db "$db" >/dev/null

  cp examples/device.json "$tmpdir/device2.json"
  python3 - "$tmpdir/device2.json" <<'PY'
  import json,sys
  p=sys.argv[1]
  obj=json.load(open(p))
  obj.setdefault("facts",{}).setdefault("disk",{})["encrypted"]=False
  json.dump(obj,open(p,"w"),indent=2)
  PY
  fleetmdm ingest "$tmpdir/device2.json" --db "$db" >/dev/null
  fleetmdm check --device mac-001 --db "$db" >/dev/null

  fleetmdm drift --device mac-001 --format json --db "$db" >/dev/null
  fleetmdm report --format json --policy disk-encryption --db "$db" >/dev/null
  ```
- Mistakes And Fixes:
  - Root cause: `Makefile` `dev` target ran `python -m fleetmdm` but the package has no `__main__` (the supported entrypoints are the `fleetmdm` console script and `python -m fleetmdm.cli`).
  - Fix: update `make dev` to run `python -m fleetmdm.cli --help`.
  - Prevention: run `make dev` as part of local smoke verification, and avoid relying on implicit package `__main__` for Typer CLIs.
  - Root cause: introduced a dynamically constructed SQL query string for `list_results_for_run`, which triggered Bandit B608.
  - Fix: refactor to explicit static query branches for each filter combination.
  - Prevention: avoid string-built SQL in security-gated code paths; prefer explicit query branches with bound parameters.
- Commits:
  `e45701d`, `cf1cc75`.
- CI:
  GitHub Actions runs `21845301456` (success) and `21845387000` (success).
- Confidence:
  High.
- Trust Label:
  `verified-local`.
- Market scan (bounded, untrusted):
  - FleetDM positions automation-first fleet visibility and MDM flows as table-stakes, including structured export/reporting via `fleetctl`. https://fleetdm.com/docs
  - Jamf Pro’s compliance benchmarks explicitly call out report exports and “audit documentation” as part of the compliance workflow. https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
  - Jamf’s Conduit docs emphasize manual and scheduled exports as a baseline expectation for inventory/report flows. https://docs.jamf.com/jamf-pro-conduit/2.40.0/Exporting_Data_with_the_Jamf_Pro_Conduit.html

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
