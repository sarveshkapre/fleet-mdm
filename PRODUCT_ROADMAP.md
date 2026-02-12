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

## Product Phase Checkpoint (2026-02-12, Session 3)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring (policy/device drill-down views): https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune report export APIs (filtered, automation-ready export jobs): https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmarks (report export + audit documentation workflows): https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
  - Kandji managed-device custom reports by blueprint/tag (filtered reporting baseline): https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
  - Fleet REST API report export surfaces (structured, API-first report retrieval): https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report

## Parity Gap Map (2026-02-12, Session 3)
- Missing:
  - Assignment hygiene visibility for stale tag assignments (`policy assignments --unmatched-tags`).
- Weak:
  - `doctor` maintenance workflow still lacks explicit integrity and optional maintenance execution.
  - Invalid `--format` handling is inconsistent across command surfaces (mixed errors/exit codes).
- Parity:
  - Report ranking/slicing (`--sort-by`, `--top`) and noise filters (`--only-failing`, `--only-skipped`).
  - JSON/JUnit/SARIF report outputs and machine-readable evidence verify output.
  - Assignment-aware policy evaluation, drift/history filters, and deterministic smoke path.
  - Evidence manifest/signature verification and signing-key lifecycle metadata.
- Differentiator:
  - Local-first, no-service-required evidence trust pipeline (manifest + signature + verify).

## Brainstormed Candidates (Ranked 2026-02-12, Session 3)
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
- [ ] `P2` Doctor enhancements: optional integrity checks + maintenance execution guidance.
- [ ] `P2` CLI consistency: normalized invalid `--format` behavior across command surfaces.
- [ ] `P2` Assignment hygiene: stale tag assignment detection (`policy assignments --unmatched-tags`).
- [ ] `P2` Config defaults file for `--db`/report/evidence settings.
- [ ] `P2` Security defaults: stricter out-of-box redaction for high-risk identifiers.
- [ ] `P3` Policy quality gate: `policy lint` for schema + semantic checks.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Cycle 1 Locked Work (This Session)
- [ ] Implement doctor maintenance parity: add `doctor --integrity-check` and optional `doctor --vacuum` flow with actionable output.
- [ ] Normalize invalid `--format` handling (consistent error text + exit code `2`) across `check`, `report`, `history`, `drift`, `doctor`, and evidence format surfaces.
- [ ] Add `policy assignments --unmatched-tags` for stale tag assignment detection.
- [ ] Update tests/docs/trackers and run verification gates (`make check`, `make security`, `make smoke` + targeted CLI smoke).

## Delivered Features
- 2026-02-12: SARIF enrichment for `report --format sarif` (`helpUri`, `fullDescription`) plus `--sarif-max-failures-per-policy` bounded failed-device samples.
- 2026-02-12: Evidence packs now support `evidence export --history-limit N` with optional `history.json` excerpts and strict-profile device redaction consistency.
- 2026-02-12: `report --sort-by` + `--top` triage controls, malformed `--since` validation in `history`/`drift`, and deterministic `make smoke` workflow.
- 2026-02-11: `report --only-assigned` and drift membership deltas via `drift --include-new-missing`.
- 2026-02-10: Python module execution parity (`python -m fleetmdm`, `python -m fleetmdm.cli`).
- 2026-02-10: report noise filters (`--only-failing`, `--only-skipped`) and CSV hardening.

## Risks And Blockers
- No external blockers identified for the current locked cycle.
- Ongoing risk: broad CLI option growth can introduce UX inconsistency; mitigate with targeted tests + docs alignment per feature.

## Next Cycle Goals (Draft)
- Deliver doctor integrity/maintenance guidance improvements.
- Normalize CLI invalid-format error behavior across command surfaces.
- Add config defaults support for common report/evidence workflows.
