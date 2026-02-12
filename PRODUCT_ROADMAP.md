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

## Product Phase Checkpoint (2026-02-12, Session 2)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring emphasizes dashboard + drill-down + monitor workflows: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune report export APIs emphasize automation-ready filtered exports: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmarks highlight audit/report exports and audit documentation expectations: https://support.jamf.com/en/articles/10932419-compliance-benchmarks-faq
  - Kandji reporting emphasizes filtered reporting workflows for managed devices: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
  - FleetDM compliance dashboard and automation docs reinforce per-device findings and exportability as baseline UX: https://fleetdm.com/docs/using-fleet/mdm/compliance-dashboard

## Parity Gap Map (2026-02-12, Session 2)
- Missing:
  - No critical missing parity items in current locked scope.
- Weak:
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
- 1) SARIF enrichment (`helpUri`, richer rule metadata, optional per-device failures cap). Score: impact 5, effort 3, fit 5, differentiation 2, risk 2, confidence 4.
- 2) Evidence export with bounded history excerpts. Score: impact 5, effort 3, fit 5, differentiation 3, risk 2, confidence 4.
- 3) Doctor integrity maintenance flags. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 4.
- 4) Config file support for defaults. Score: impact 3, effort 4, fit 4, differentiation 2, risk 2, confidence 3.
- 5) Strict evidence default redaction for serial/hardware IDs. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 6) CLI invalid `--format` normalization across commands. Score: impact 3, effort 2, fit 4, differentiation 1, risk 1, confidence 4.
- 7) Assignment stale-tag detection (`policy assignments --unmatched-tags`). Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 8) Synthetic performance bench + index tuning follow-up. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 9) Exporter secure-boot parity. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 10) Packaging docs (Homebrew/Nix + checksum guidance). Score: impact 2, effort 3, fit 3, differentiation 1, risk 1, confidence 3.

## Pending Features
- [ ] `P2` Doctor enhancements: `--integrity-check` and maintenance guidance.
- [ ] `P2` Config defaults file for `--db`/report/evidence settings.
- [ ] `P2` Security defaults: stricter out-of-box redaction for high-risk identifiers.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Cycle 1 Locked Work (This Session)
- [x] Implement SARIF quality upgrade: richer rule metadata + optional bounded per-device failure context.
- [x] Implement evidence export bounded history excerpts via `--history-limit`.
- [x] Update tests/docs/trackers and run verification gates (`make check`, `make security`, `make smoke` + targeted CLI smoke).

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
