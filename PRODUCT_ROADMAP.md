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

## Product Phase Checkpoint (2026-02-12)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring emphasizes dashboard + drill-down + monitor workflows: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune report export APIs emphasize automation-ready filtered exports: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmarks highlight audit/report exports and audit documentation expectations: https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
  - Kandji device views emphasize sort/filter/export workflows: https://support.kandji.io/kb/device-views-overview
  - Kandji Prism documents API-first query/filter/export posture: https://support.kandji.io/kb/prism
  - FleetDM positions API + CLI automation as baseline operations model: https://fleetdm.com/docs/rest-api/rest-api

## Parity Gap Map (2026-02-12)
- Missing:
  - No critical missing parity items in the locked cycle scope.
- Weak:
  - SARIF metadata depth and bounded per-device context.
  - Evidence packs missing bounded history excerpts for auditors.
  - Doctor maintenance workflow guidance (`VACUUM`/integrity checks).
- Parity:
  - Report ranking/slicing (`--sort-by`, `--top`) for triage workflows.
  - Clear validation for malformed `--since` timestamps in history/drift paths.
  - Canonical deterministic `make smoke` target for local release verification.
  - JSON/JUnit/SARIF report outputs.
  - Assignment-aware policy resolution.
  - Drift and history filters for basic scale.
  - Evidence manifest/signature verification and key lifecycle metadata.
- Differentiator:
  - Local-first, no-service-required evidence trust pipeline (manifest + signature + verify).

## Brainstormed Candidates (Ranked 2026-02-12)
- 1) Report triage controls (`--sort-by`, `--top`). Score: impact 5, effort 2, fit 5, differentiation 2, risk 1, confidence 5.
- 2) Strict CLI `--since` validation with clear error messages. Score: impact 5, effort 1, fit 5, differentiation 1, risk 1, confidence 5.
- 3) Deterministic `make smoke` workflow. Score: impact 4, effort 2, fit 5, differentiation 1, risk 1, confidence 5.
- 4) Evidence export with bounded history excerpts. Score: impact 4, effort 3, fit 4, differentiation 3, risk 2, confidence 4.
- 5) SARIF enrichment (`helpUri`, richer rule metadata, optional per-device failures cap). Score: impact 4, effort 3, fit 4, differentiation 2, risk 2, confidence 4.
- 6) Doctor integrity maintenance flags. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 4.
- 7) Config file support for defaults. Score: impact 3, effort 4, fit 4, differentiation 2, risk 2, confidence 3.
- 8) Synthetic performance bench + index tuning follow-up. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 9) Strict evidence default redaction for serial/hardware IDs. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 10) Exporter secure-boot parity. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.

## Pending Features
- [ ] `P2` SARIF quality: bounded per-device failures and richer `rule` metadata.
- [ ] `P2` Evidence packs: optional bounded `history` excerpts.
- [ ] `P2` Doctor enhancements: `--integrity-check` and maintenance guidance.
- [ ] `P2` Config defaults file for `--db`/report/evidence settings.
- [ ] `P2` Security defaults: stricter out-of-box redaction for high-risk identifiers.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Cycle 1 Locked Work (This Session)
- [x] Implement report triage controls (`--sort-by`, `--top`) with tests/docs.
- [x] Implement `--since` validation for history/drift with tests/docs.
- [x] Add `make smoke` and document/run it as part of verification evidence.

## Delivered Features
- 2026-02-12: `report --sort-by` + `--top` triage controls, malformed `--since` validation in `history`/`drift`, and deterministic `make smoke` workflow.
- 2026-02-11: `report --only-assigned` and drift membership deltas via `drift --include-new-missing`.
- 2026-02-10: Python module execution parity (`python -m fleetmdm`, `python -m fleetmdm.cli`).
- 2026-02-10: report noise filters (`--only-failing`, `--only-skipped`) and CSV hardening.

## Risks And Blockers
- No external blockers identified for the current locked cycle.
- Ongoing risk: broad CLI option growth can introduce UX inconsistency; mitigate with targeted tests + docs alignment per feature.

## Next Cycle Goals (Draft)
- Deliver SARIF metadata depth improvements.
- Add evidence-history excerpt export option with size bounds.
- Decide whether dashboard work remains justified after CLI parity improvements.
