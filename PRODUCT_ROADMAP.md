# Product Roadmap

## Product Goal
- Keep fleet-mdm production-ready as a local-first compliance tool for inventory ingest, policy evaluation, and audit-grade evidence workflows.

## Definition Of Done
- Core feature set supports real repeated usage for inventory, policy checks, triage, drift, and evidence export/verify.
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

## Session Goal Checkpoint (2026-02-12, Session 3)
- Goal (one sentence):
  Deliver the highest-impact reliability/UX parity work by improving `doctor` maintenance actionability and normalizing CLI format-error behavior.
- Success Criteria:
  - `doctor` supports optional integrity checks and optional `VACUUM` maintenance execution with actionable output in both table/json modes.
  - `check`/`report`/`history`/`drift`/`doctor` and evidence format surfaces reject invalid `--format` consistently (same error shape, exit code `2`).
  - Relevant tests and local verification gates pass; docs and trackers are aligned.
- Non-goals:
  - Config defaults system for report/evidence/db options.
  - Optional read-only dashboard work.
  - New agent/exporter data collection beyond existing schema.
- Selected Tasks (locked for this session):
  - Doctor maintenance parity (`--integrity-check`, `--vacuum`).
  - Cross-command invalid `--format` normalization.

## Product Phase Checkpoint (2026-02-12, Session 4)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring (policy/device drill-down + assignment monitoring): https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune export report APIs (filtered, automation-ready export jobs): https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmarks (benchmarks + evidence/audit workflows): https://www.jamf.com/blog/how-to-build-compliance-benchmarks-for-your-organization/
  - Kandji managed-device custom reports by blueprint/tag (filtered reporting baseline): https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
  - Fleet REST API report export surfaces (structured, API-first report retrieval): https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report

## Parity Gap Map (2026-02-12, Session 4)
- Missing:
  - No critical missing item in this just-completed locked scope.
- Weak:
  - Config defaults for repeated report/evidence/db workflows are not yet available.
- Parity:
  - Report ranking/slicing (`--sort-by`, `--top`) and noise filters (`--only-failing`, `--only-skipped`).
  - JSON/JUnit/SARIF report outputs and machine-readable evidence verify output.
  - Assignment-aware policy evaluation, drift/history filters, and deterministic smoke path.
  - Evidence manifest/signature verification and signing-key lifecycle metadata.
- Differentiator:
  - Local-first, no-service-required evidence trust pipeline (manifest + signature + verify).

## Brainstormed Candidates (Ranked 2026-02-12, Session 4)
- 1) Doctor integrity + maintenance controls (`--integrity-check`, `--vacuum`) with JSON/reporting output. Score: impact 4, effort 3, fit 5, differentiation 2, risk 2, confidence 4.
- 2) Normalize invalid `--format` handling across CLI command surfaces. Score: impact 4, effort 2, fit 5, differentiation 1, risk 1, confidence 4.
- 3) Assignment stale-tag detection (`policy assignments --unmatched-tags`). Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 4) Config defaults support for `--db`/report/evidence paths. Score: impact 3, effort 4, fit 4, differentiation 2, risk 2, confidence 3.
- 5) Security defaults for strict evidence redaction of high-risk identifiers. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 6) Policy lint command (`policy lint`) for pre-DB schema + semantic checks. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 7) Linux exporter secure-boot parity fields. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 8) Synthetic large-fleet benchmark and index follow-up. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 9) Packaging docs (Homebrew/Nix + checksum verification guidance). Score: impact 2, effort 3, fit 3, differentiation 1, risk 1, confidence 3.
- 10) Optional read-only dashboard scaffold. Score: impact 2, effort 5, fit 3, differentiation 3, risk 3, confidence 2.

## Pending Features
- [ ] `P2` Config defaults file for `--db`/report/evidence settings.
- [ ] `P2` Security defaults: stricter out-of-box redaction for high-risk identifiers.
- [ ] `P3` Policy quality gate: `policy lint` for schema + semantic checks.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Pending Feature Check (2026-02-12, Session 3)
- Question: What features are still pending?
- Answer: Remaining work is now config defaults, stricter security defaults, policy lint, exporter parity, benchmark/tuning follow-up, packaging docs, and optional dashboard.

## Cycle 1 Locked Work (This Session)
- [x] Implement doctor maintenance parity: add `doctor --integrity-check` and optional `doctor --vacuum` flow with actionable output.
- [x] Normalize invalid `--format` handling (consistent error text + exit code `2`) across `check`, `report`, `history`, `drift`, `doctor`, and evidence format surfaces.
- [x] Add assignment stale-tag detection: `policy assignments --unmatched-tags`.
- [x] Update tests/docs/trackers and run verification gates (`make check`, `make security`, `make smoke` + targeted CLI smoke).

## Delivered Features
- 2026-02-12: `doctor` maintenance parity shipped with `--integrity-check` and `--vacuum`, including before/after maintenance metrics in JSON/table output.
- 2026-02-12: invalid `--format` handling normalized across core/evidence surfaces with consistent validation messaging and exit code `2`.
- 2026-02-12: assignment hygiene command shipped: `policy assignments --unmatched-tags` for stale tag assignment detection.
- 2026-02-12: SARIF enrichment for `report --format sarif` (`helpUri`, `fullDescription`) plus `--sarif-max-failures-per-policy` bounded failed-device samples.
- 2026-02-12: Evidence packs now support `evidence export --history-limit N` with optional `history.json` excerpts and strict-profile device redaction consistency.
- 2026-02-12: `report --sort-by` + `--top` triage controls, malformed `--since` validation in `history`/`drift`, and deterministic `make smoke` workflow.
- 2026-02-11: `report --only-assigned` and drift membership deltas via `drift --include-new-missing`.
- 2026-02-10: Python module execution parity (`python -m fleetmdm`, `python -m fleetmdm.cli`).
- 2026-02-10: report noise filters (`--only-failing`, `--only-skipped`) and CSV hardening.

## Risks And Blockers
- No feature blockers identified for the current locked cycle.
- Ongoing risk: broad CLI option growth can introduce UX inconsistency; mitigate with targeted tests + docs alignment per feature.
- Environment-only blocker: network-restricted runtime prevents online dependency resolution for `make build` and online vulnerability lookups for `pip_audit`.

## Next Cycle Goals (Draft)
- Add config defaults support for common report/evidence workflows.
- Add policy quality preflight (`policy lint`) and tighten JSON-mode failure taxonomy.
