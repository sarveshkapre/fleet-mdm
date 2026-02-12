# Product Roadmap

## Product Goal
- Keep fleet-mdm production-ready as a local-first compliance tool for inventory ingest, policy evaluation, and audit-grade evidence workflows.

## Definition Of Done
- Core feature set supports repeated real usage for inventory, policy checks, triage, drift, and evidence export/verify.
- CLI UX is robust for scale (filters, sorting, bounded outputs, clear errors).
- No open critical reliability/security issues in local verification gates.
- Lint, typecheck, tests, build, and security checks pass and are documented with command evidence.
- README and docs reflect shipped behavior.

## Milestones
- `M1 Foundation` (completed): inventory ingest, policy CRUD, check/report basics, local DB lifecycle.
- `M2 Core Features` (completed): assignments, history, drift, evidence export/verify/signing/key lifecycle, machine-readable outputs.
- `M3 Reliability + Scale UX` (current): triage ergonomics, input validation hardening, deterministic smoke verification paths.
- `M4 Optional UI/UX Surface` (pending): lightweight read-only dashboard (if still justified after CLI parity).
- `M5 Stabilization + Release Readiness` (pending): release process hardening, packaging docs, final operational polish.

## Current Milestone
- `M3 Reliability + Scale UX`

## Session Goal Checkpoint (2026-02-12, Session 6)
- Goal (one sentence):
  Ship explicit JSON failure taxonomy (`code`, `message`) for machine-readable FleetMDM command failures.
- Success Criteria:
  - Non-success JSON responses for `check`, `report`, `history`, `drift`, `policy lint`, and `evidence verify` include `error.code` and `error.message`.
  - Text/table workflows keep current behavior (no regression in human-readable UX).
  - Local verification gates (`make lint`, `make typecheck`, `pytest -q`, smoke path) pass and docs/trackers are synchronized.
- Non-goals:
  - Optional read-only dashboard work.
  - Exporter parity work (Linux secure-boot, extra macOS posture fields).
  - Packaging automation and distribution-channel changes.
- Selected Tasks (locked for this session):
  - Add shared JSON error-envelope helper and stable error codes.
  - Wire non-success JSON-mode paths in `check`/`report`/`history`/`drift`/`policy lint` and evidence verification.
  - Add regression tests and update docs/trackers.

## Product Phase Checkpoint (2026-02-12, Session 6)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring surface (device/policy compliance state): https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune export/report API expectations for automation pipelines: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmark reporting/export expectations: https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
  - Fleet REST API report export baseline (`hosts/report` CSV): https://fleetdm.com/docs/rest-api
  - Kandji tag-based scoping baseline for device cohorts: https://support.kandji.io/kb/tags-for-devices

## Parity Gap Map (2026-02-12, Session 6)
- Missing:
  - Explicit JSON error taxonomy for failed machine-readable command paths.
  - Exporter parity for Linux secure-boot posture in examples/schema guidance.
- Weak:
  - Strict-profile redaction defaults/trust-boundary docs for high-risk identifiers.
  - Synthetic large-fleet benchmark evidence for `report`/`history`/`drift`.
- Parity:
  - Config defaults for `db`, `report.*`, and `evidence_export.*`.
  - Policy preflight quality gate (`policy lint`) with schema + semantic checks.
  - Assignment-aware checks/reporting, drift/history filters, and JSON/JUnit/SARIF outputs.
- Differentiator:
  - Local-first evidence trust pipeline (manifest + optional signature + verify) with no hosted dependency.

## Brainstormed Candidates (Ranked 2026-02-12, Session 6)
- 1) JSON failure taxonomy (`code`, `message`) across JSON command failures. Score: impact 5, effort 3, fit 5, differentiation 2, risk 2, confidence 4. (selected)
- 2) Strict redaction defaults/trust-boundary docs for high-risk identifiers. Score: impact 4, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 3) Linux secure-boot exporter parity + schema guidance. Score: impact 4, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 4) `report --output <file>` direct artifact writing for CI operators. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- 5) `evidence verify --strict` to fail on warnings in pipelines. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- 6) `history prune --before <ts>` retention tooling for local DB lifecycle control. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 7) `db backup` command using SQLite online backup API. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 8) Synthetic 10k-row benchmark harness for report/drift/history tuning evidence. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 9) Packaging docs (Homebrew/Nix + checksum verification). Score: impact 2, effort 3, fit 3, differentiation 1, risk 1, confidence 3.
- 10) Optional read-only dashboard for triage/evidence status. Score: impact 2, effort 5, fit 3, differentiation 3, risk 3, confidence 2.

## Pending Features
- [ ] `P2` Reliability: explicit JSON failure taxonomy (`code`, `message`) for machine-readable command failures.
- [ ] `P2` Security defaults: stricter out-of-box redaction guidance for high-risk identifiers.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Pending Feature Check (2026-02-12, Session 6)
- Question: What features are still pending?
- Answer: JSON error taxonomy, strict redaction defaults/docs, exporter parity, benchmark/tuning follow-up, packaging docs, and optional dashboard.

## Cycle 2 Locked Work (Session 6)
- [ ] Add shared JSON failure envelope (`code`, `message`) for machine-readable command errors.
- [ ] Wire JSON failure payloads for `check`/`report`/`history`/`drift`/`policy lint` and evidence verify.
- [ ] Add/adjust regression tests for JSON-mode non-success paths.
- [ ] Update docs/trackers and record full verification evidence.

## Delivered Features
- 2026-02-12: `make security` now runs `pip_audit` with configurable writable cache path (`PIP_AUDIT_CACHE_DIR`, default `/tmp/pip-audit-cache`) to avoid sandbox permission failures.
- 2026-02-12: Config-default support shipped via `FLEETMDM_CONFIG` (or `~/.fleetmdm/config.yaml`) for `db`, report defaults, and evidence export defaults.
- 2026-02-12: `fleetmdm policy lint` shipped with schema + semantic checks, recursive directory support, and JSON/text output.
- 2026-02-12: `doctor` maintenance parity shipped with `--integrity-check` and `--vacuum`, including before/after maintenance metrics in JSON/table output.
- 2026-02-12: Invalid `--format` handling normalized across core/evidence surfaces with consistent validation messaging and exit code `2`.
- 2026-02-12: Assignment hygiene command shipped: `policy assignments --unmatched-tags` for stale tag assignment detection.
- 2026-02-12: SARIF enrichment for `report --format sarif` (`helpUri`, `fullDescription`) plus `--sarif-max-failures-per-policy` bounded failed-device samples.
- 2026-02-12: Evidence packs now support `evidence export --history-limit N` with optional `history.json` excerpts and strict-profile device redaction consistency.
- 2026-02-11: `report --only-assigned` and drift membership deltas via `drift --include-new-missing`.
- 2026-02-10: Python module execution parity (`python -m fleetmdm`, `python -m fleetmdm.cli`).
- 2026-02-10: Report noise filters (`--only-failing`, `--only-skipped`) and CSV hardening.

## Risks And Blockers
- No open feature blockers for this locked cycle.
- Ongoing risk: broad CLI option growth can introduce UX inconsistency; mitigate with targeted tests + docs alignment per feature.
- Environment-only blocker: network-restricted runtime prevents online dependency resolution for `make build` and online vulnerability lookups for `pip_audit`.

## Next Cycle Goals (Draft)
- Add JSON failure taxonomy (`code`, `message`) for machine-readable failure paths.
- Tighten strict-profile redaction defaults/trust-boundary docs.
- Add Linux secure-boot exporter parity and benchmark evidence for scale paths.
