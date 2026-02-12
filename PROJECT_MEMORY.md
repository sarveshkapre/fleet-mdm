# Project Memory

## Historical Summary
- 2026-02-12T18:10:33Z: compacted memory from 504 lines. Full snapshot archived at /Users/sarvesh/code/fleet-mdm/.clone_memory_archive/PROJECT_MEMORY-20260212T181033Z.md

- Mistakes And Fixes:
  - Environment constraint: `pip_audit` default cache path was not writable inside sandbox.
  - Remediation: run `pip_audit` with explicit writable cache dir (`--cache-dir /tmp/pip-audit-cache`) and record offline-network limitation separately.
- Commit:
  `a61da2c`.
- Confidence:
  High on feature behavior and tests; medium on full release gate due network-restricted build/security dependency resolution.
- Trust Label:
  `trusted` for local edits/tests/smoke, `untrusted` for external references.

## 2026-02-12 - Cycle 1 - Session 5 (Pre-Implementation Checkpoint)
- Session Notes:
  - Goal: ship the highest-impact pending M3 items by finalizing config defaults and delivering `policy lint`.
  - Success Criteria:
    - Config defaults are honored for `db`, `report`, and `evidence_export`, with CLI flags taking precedence.
    - `fleetmdm policy lint` supports file/directory inputs, optional recursion, and text/json output with semantic validation.
    - Verification gates (`make lint`, `make typecheck`, `make test`, `make smoke`) pass and docs/trackers are updated.
  - Non-goals:
    - Optional dashboard work.
    - New exporter feature collection work.
    - Packaging/release automation expansion.
  - Planned Tasks (locked for this cycle):
    - Complete config-default resolution helpers and apply them across CLI command surfaces.
    - Implement/verify `policy lint` schema + semantic checks and machine-readable output.
    - Keep invalid `--format` behavior consistent (`exit 2`, clear message, no traceback).
    - Update roadmap/feature/memory docs and record exact verification evidence.
- Product phase checkpoint:
  - Are we in a good product phase yet? `No`.
  - Best-in-market references (bounded, untrusted):
    - Microsoft Intune compliance monitoring: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
    - Microsoft Intune export report APIs: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
    - Jamf compliance benchmark workflows: https://www.jamf.com/blog/how-to-build-compliance-benchmarks-for-your-organization/
    - Kandji managed-device custom reports by blueprint/tag: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
    - Fleet REST API report export endpoint expectations: https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report
- Gap map (session 5):
  - Missing: explicit JSON failure taxonomy (`code`, `message`) for machine-readable non-success paths.
  - Weak: strict redaction defaults/trust-boundary guidance; Linux secure-boot exporter parity.
  - Parity: config defaults and policy preflight linting after this cycle.
  - Differentiator: local-first evidence trust pipeline (manifest/sign/verify).
- Ranked candidate scoring (impact, effort, fit, differentiation, risk, confidence):
  - 1) Config defaults (`db`, `report.*`, `evidence_export.*`): 4,3,5,2,2,4. (selected)
  - 2) Policy lint command with semantic checks: 4,3,5,2,2,4. (selected)
  - 3) Invalid `--format` consistency hardening: 4,2,5,1,1,4. (selected)
  - 4) JSON failure taxonomy: 4,3,4,2,2,3.
  - 5) Strict redaction defaults docs: 3,2,4,2,1,4.
- What features are still pending?
  - From `PRODUCT_ROADMAP.md`: JSON failure taxonomy, stricter redaction defaults/docs, exporter parity, performance benchmarking, packaging docs, dashboard.
  - From `CLONE_FEATURES.md`: 20+ pending backlog candidates remain after locking this cycle.
- Planned verification commands:
  - `make lint`
  - `make typecheck`
  - `make test`
  - `make smoke`
  - `make security`
  - `make check`
  - `make build`
- Trust Label:
  `trusted` for local planning/code context; `untrusted` for external market references.

## 2026-02-12 - Cycle 1 - Session 5 (Implementation: Policy Lint + Config Defaults)
- Recent Decisions:
  - Finish the locked scope (`policy lint` + config defaults) before taking additional roadmap work.
  - Keep CLI override precedence for every config defaulted option.
  - Harden `make security` so environment cache permissions do not fail early.
- Why:
  - `policy lint` catches policy defects before runtime compliance checks.
  - Config defaults reduce repeated operator flags while preserving deterministic automation.
  - Security checks should fail only for meaningful reasons, not cache-path permissions.
- What changed:
  - Added `fleetmdm policy lint` with file/directory input, optional `--recursive`, and `--format text|json`.
  - Added semantic lint checks for invalid regex patterns, invalid `in`/`not_in` value shape, invalid target shapes, and duplicate-tag warnings.
  - Added config defaults loading from `~/.fleetmdm/config.yaml` or `FLEETMDM_CONFIG`.
  - Added config-driven defaults for DB resolution across CLI commands and for `report`/`evidence export` option sets.
  - Kept invalid `--format` message shape consistent and ensured tests enforce it.
  - Updated `Makefile` `security` target to run `pip_audit` with writable default cache dir (`PIP_AUDIT_CACHE_DIR`, default `/tmp/pip-audit-cache`).
  - Updated docs: README quickstart behavior, changelog, roadmap/project docs, and trackers.
- Verification Evidence:
  - `make lint` (pass)
  - `make typecheck` (pass)
  - `make test` (pass, `58 passed`)
  - `make smoke` (pass)
  - `make security` (fail: DNS/network restriction resolving `pypi.org`; no cache-permission failure after Makefile update)
  - `.venv/bin/python -m bandit -q -r src` (pass)
  - `make build` (fail: offline dependency resolution for `hatchling>=1.24.0`)
  - `make check` (partial pass: lint/type/test pass; build fails from same offline dependency resolution)
  - Local config/lint smoke (pass):
    ```bash
    tmpdir=$(mktemp -d)
    config="$tmpdir/fleet-config.yaml"
    db="$tmpdir/fleet.db"
    policy="$tmpdir/policy.yaml"
    invalid_dir="$tmpdir/policies"
    mkdir -p "$invalid_dir/nested"
    # writes valid/invalid policies and config defaults
    # runs seed/report/check/evidence export/policy lint
    # validates report/lint JSON payloads
    # prints: smoke-ok
    rm -rf "$tmpdir"
    ```
- Mistakes And Fixes:
  - Root cause: `make security` used `pip_audit` defaults that touched an unwritable cache location in this sandbox.
  - Fix: parameterized cache path in `Makefile` using `PIP_AUDIT_CACHE_DIR` defaulting to `/tmp/pip-audit-cache`.
  - Prevention rule: keep security-tool cache/output paths explicitly writable in automation targets.
- Commit:
  `64f6c74`
- Confidence:
  High on local feature behavior/tests; medium on release-gate completeness due network-restricted build/audit calls.
- Trust Label:
  `trusted` for local code/tests/smoke; `untrusted` for market references.

## 2026-02-12 - Cycle 1 - Session 5B (Stabilization Verification Addendum)
- Recent Decisions:
  - Preserve locked scope and avoid new feature expansion while repairing intermediate local breakage in `src/fleetmdm/cli.py`.
  - Re-verify with focused smoke for the exact touched flows (`policy lint` and config defaults).
- Why:
  - Intermediate local edits briefly left the tree in a broken state; the highest-impact action was restoring deterministic behavior and proving it with repeatable checks.
- Verification Evidence:
  - `make lint` (pass)
  - `make typecheck` (pass)
  - `.venv/bin/python -m pytest -q` (pass, `58 passed`)
  - Local smoke (pass, validated config defaults + policy lint payload semantics):
    ```bash
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    cat > "$tmpdir/config.yaml" <<'YAML'
    db: "$tmpdir/fleet.db"
    report:
      format: json
      sort_by: failed
      top: 1
    evidence_export:
      output: "$tmpdir/evidence"
      redaction_profile: strict
      history_limit: 1
    YAML
    FLEETMDM_CONFIG="$tmpdir/config.yaml" .venv/bin/python -m fleetmdm seed >/dev/null
    FLEETMDM_CONFIG="$tmpdir/config.yaml" .venv/bin/python -m fleetmdm report >/tmp/fleetmdm-config-report.json
    FLEETMDM_CONFIG="$tmpdir/config.yaml" .venv/bin/python -m fleetmdm check --device mac-001 --format json >/dev/null
    FLEETMDM_CONFIG="$tmpdir/config.yaml" .venv/bin/python -m fleetmdm evidence export >/dev/null
    mkdir -p "$tmpdir/policies/nested"
    cat > "$tmpdir/policies/valid.yaml" <<'YAML'
    id: min-os
    name: Minimum OS Version
    checks:
      - key: os_version
        op: version_gte
        value: "14.0"
    YAML
    cat > "$tmpdir/policies/nested/invalid.yaml" <<'YAML'
    id: bad
    name: Bad Regex
    checks:
      - key: os_version
        op: regex
        value: "["
    YAML
    .venv/bin/python -m fleetmdm policy lint "$tmpdir/policies" --recursive --format json >/tmp/fleetmdm-policy-lint.json
    ```
- Mistakes And Fixes:
  - Root cause: one smoke attempt used `python` from PATH, which was unavailable in this shell.
  - Fix: reran verification with explicit `.venv/bin/python`.
  - Prevention rule: use explicit virtualenv interpreter paths in documented smoke commands.
- Commit:
  `64f6c74`
- Confidence:
  High.
- Trust Label:
  `trusted` (local code/tests/smoke).

## 2026-02-12 - Cycle 1 - Session 4 (Pre-Implementation Checkpoint)
- Session Notes:
  - Goal: ship the remaining locked M3 reliability/parity work for doctor maintenance controls, format-validation consistency, and stale assignment hygiene.
  - Success Criteria:
    - `fleetmdm doctor` supports `--integrity-check` and optional `--vacuum` with explicit text/JSON reporting.
    - Invalid `--format` values return consistent error text and exit code `2` across `check`, `report`, `history`, `drift`, `doctor`, `evidence key list`, and `evidence verify`.
    - `fleetmdm policy assignments --unmatched-tags` surfaces stale tag assignments with clear operator output.
    - Verification gates (`make check`, `make security`, `make smoke`) and targeted CLI smoke pass and are recorded.
  - Non-goals:
    - No dashboard/UI work in this session.
    - No config defaults file work in this session.
    - No schema redesign or non-roadmap expansion.
  - Planned Tasks (locked for this cycle):
    - Implement `doctor --integrity-check` and `doctor --vacuum`.
    - Normalize invalid-format behavior across targeted command surfaces.
    - Add `policy assignments --unmatched-tags`.
    - Update tests/docs/trackers and run full verification commands.
- Product phase checkpoint:
  - Are we in a good product phase yet? `No`.
  - Best-in-market baseline references (bounded, untrusted):
    - Intune compliance monitor baseline: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
    - Intune export report APIs baseline: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
    - Jamf compliance benchmark workflow expectations: https://www.jamf.com/blog/how-to-build-compliance-benchmarks-for-your-organization/
    - Kandji filtered managed-device custom reports by tag/blueprint: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
    - Fleet structured report export API expectations: https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report
- Gap map (session 4):
  - Missing: stale tag assignment visibility in assignment tooling.
  - Weak: doctor maintenance execution flow and format-validation consistency across commands.
  - Parity: assignment-aware report/drift/history behavior and machine-readable evidence/report outputs.
  - Differentiator: local-first evidence trust pipeline with deterministic manifests and signature verification.
- Ranked candidate scoring (impact, effort, fit, differentiation, risk, confidence):
  - 1) Doctor maintenance parity (`--integrity-check`, `--vacuum`): 4,3,5,2,2,4.
  - 2) CLI invalid `--format` normalization: 4,2,5,1,1,4.
  - 3) Assignment stale-tag detection (`policy assignments --unmatched-tags`): 3,2,4,2,1,4.
  - 4) Config defaults support (deferred): 3,4,4,2,2,3.
  - 5) Policy lint command (deferred): 3,3,4,2,2,3.
- What features are still pending?
  - From `PRODUCT_ROADMAP.md`: doctor enhancements, format normalization, assignment stale-tag detection, config defaults, stricter redaction defaults, policy lint, exporter parity, performance benchmarking, packaging docs, dashboard.
  - From `CLONE_FEATURES.md`: 20+ pending backlog items remain after locking this cycle.
- Planned verification commands:
  - `make check`
  - `make security`
  - `make smoke`
  - targeted CLI smoke for `doctor` and `policy assignments --unmatched-tags`.
- Trust Label:
  `trusted` for local repo planning; `untrusted` for external market references.

## 2026-02-12 - Cycle 1 - Session 3 (Pre-Implementation Checkpoint)
- Session Notes:
  - Goal: close the highest-impact remaining reliability/parity gaps in FleetMDM CLI workflows for doctor maintenance and format validation consistency.
  - Success Criteria:
    - `fleetmdm doctor` supports optional integrity execution and optional `VACUUM` maintenance with clear text/JSON reporting.
    - Invalid `--format` inputs fail consistently (clear error + exit code `2`) across targeted command surfaces.
    - Tests and verification gates (`make check`, `make security`, `make smoke`, targeted CLI smoke) pass and are recorded.
  - Non-goals:
    - No read-only dashboard work this session.
    - No config defaults file implementation this session.
    - No schema/storage redesign beyond targeted reliability updates.
  - Planned Tasks (locked for this cycle):
    - Implement doctor parity features (`--integrity-check`, `--vacuum`) and wire JSON/table output.
    - Normalize invalid `--format` behavior across `check`, `report`, `history`, `drift`, `doctor`, `evidence key list`, and `evidence verify`.
    - Add `policy assignments --unmatched-tags` stale assignment detection.
    - Update tests/docs/trackers and execute verification gates.
- Product phase checkpoint:
  - Are we in a good product phase yet? `No`.
  - Best-in-market baseline references (bounded, untrusted):
    - Intune compliance monitor workflow: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
    - Intune export report APIs: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
    - Jamf compliance benchmark/audit workflow expectations: https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
    - Kandji filtered managed-device reports by blueprint/tag: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
    - Fleet REST API report export endpoint: https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report
- Gap map (session 3):
  - Missing: no critical missing parity item in current locked scope.
  - Weak: doctor maintenance workflow (`integrity_check`/`VACUUM`) and invalid `--format` consistency.
  - Parity: assignment-aware reporting, drift/history filters, SARIF/JUnit/JSON outputs, evidence trust pipeline.
  - Differentiator: local-first audit evidence with manifest + signature verify.
- What features are still pending?
  - From `PRODUCT_ROADMAP.md`: doctor enhancements, format normalization, stale tag detection, config defaults, stricter security defaults, exporter parity, benchmarking, packaging docs, dashboard.
  - From `CLONE_FEATURES.md`: 20+ candidate backlog items remain after locking this cycle.
- Planned verification commands:
  - `make check`
  - `make security`
  - `make smoke`
  - targeted CLI smoke for new flags/paths.
- Trust Label:
  `trusted` for local repo analysis/planning; `untrusted` for external market references.

## 2026-02-12 - Cycle 1 - Session 3 (Implementation: Doctor Maintenance + Format Parity)
- Recent Decisions:
  - Keep execution locked to doctor maintenance parity and cross-command format validation consistency; treat assignment stale-tag visibility as already-shipped code and verify it with smoke evidence instead of re-implementing.
  - Refactor doctor metrics collection through a single snapshot helper to reduce drift between before/after maintenance reporting.
- Why:
  - The highest-impact open reliability gaps were operational DB remediation and predictable CLI automation failures on invalid formats.
- What changed:
  - Added/standardized `_normalize_choice_option` usage across `check`, `report`, `history`, `drift`, `doctor`, `evidence key list`, and `evidence verify`.
  - Hardened `doctor` maintenance flow: optional `--integrity-check`, optional `--vacuum`, before/after freelist/page/size metrics, reclaimed-bytes reporting, and clearer maintenance warnings.
  - Added regression tests for doctor maintenance JSON output and invalid-format behavior across core/evidence command surfaces.
  - Verified stale tag assignment output (`policy assignments --unmatched-tags`) and updated roadmap/feature trackers to reflect delivered status.
- Verification Evidence:
  - `make check` (partial pass: lint/type/tests passed; build step failed in network-restricted environment when resolving `hatchling>=1.24.0`).
  - `.venv/bin/python -m pip_audit --cache-dir /tmp/pip-audit-cache` (failed: DNS/network restriction to `pypi.org`).
  - `.venv/bin/python -m bandit -q -r src` (pass).
  - `make smoke` (pass).
  - Targeted doctor/format smoke (pass):
    ```bash
    tmpdir=$(mktemp -d)
    db="$tmpdir/fleet.db"
    .venv/bin/python -m fleetmdm seed --db "$db" >/dev/null
    .venv/bin/python -m fleetmdm doctor --db "$db" --format json --integrity-check --vacuum >/dev/null
    .venv/bin/python -m fleetmdm report --db "$db" --format invalid >/tmp/fleetmdm-invalid-format.txt 2>&1
    test "$?" -eq 2
    rm -rf "$tmpdir"
    ```
  - Targeted assignment-hygiene smoke (pass):
    ```bash
    tmpdir=$(mktemp -d)
    db="$tmpdir/fleet.db"
    .venv/bin/python -m fleetmdm seed --db "$db" >/dev/null
    .venv/bin/python -m fleetmdm policy assign min-os-version --tag nonexistent --db "$db" >/dev/null
    .venv/bin/python -m fleetmdm policy assignments --db "$db" --unmatched-tags >/tmp/fleetmdm-unmatched-tags.txt
    rm -rf "$tmpdir"
    ```
- Mistakes And Fixes:
  - Root cause: used reserved/read-only `status` shell variable during smoke scripting in `zsh`.
  - Fix: switched to `rc` for exit-code capture.
  - Prevention rule: avoid shell-reserved names (`status`, `pipestatus`, etc.) in scripted verification snippets.
- Commit:
  `d7cce76`, `616604f`.
- Confidence:
  High on local CLI behavior/tests; medium on full release gate because build and online vulnerability lookup are blocked by network constraints.
- Trust Label:
  `trusted` for local code/tests/smoke; `untrusted` for external market references.

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
