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

## Session Goal Checkpoint (2026-02-12, Session 5)
- Goal (one sentence):
  Ship the highest-value remaining M3 parity work by finalizing config-default behavior and delivering `policy lint` with reliable machine-readable output.
- Success Criteria:
  - `fleetmdm policy lint` works for file and directory inputs (recursive optional) with text/json output and semantic validation.
  - Config defaults (`FLEETMDM_CONFIG` / `~/.fleetmdm/config.yaml`) are honored for DB path, report defaults, and evidence export defaults.
  - Local validation (`make lint`, `make typecheck`, `pytest -q`) passes and docs/trackers are synchronized.
- Non-goals:
  - Optional read-only dashboard work.
  - New agent/exporter data collection features.
  - Release packaging automation changes.
- Selected Tasks (locked for this session):
  - Deliver and test `policy lint` parity.
  - Complete config-default resolution helpers and wire them to command surfaces.
  - Keep invalid `--format` validation consistent with no traceback noise.

## Product Phase Checkpoint (2026-02-12, Session 5)
- Are we in a good product phase yet? `No`.
- Best-in-market references (bounded market scan, untrusted):
  - Microsoft Intune compliance monitoring: https://learn.microsoft.com/en-us/intune/intune-service/protect/compliance-policy-monitor
  - Microsoft Intune export report APIs: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-apis
  - Jamf compliance benchmark workflows: https://www.jamf.com/blog/how-to-build-compliance-benchmarks-for-your-organization/
  - Kandji managed-device custom reports by blueprint/tag: https://support.kandji.io/kb/create-custom-reports-with-managed-devices-by-blueprint-and-tag
  - Fleet REST API report export surfaces: https://fleetdm.com/docs/rest-api/rest-api#post-api-v1-fleet-hosts-report

## Parity Gap Map (2026-02-12, Session 5)
- Missing:
  - JSON-mode error taxonomy (`code`, `message`) for non-success machine-readable command failures.
  - Exporter parity for Linux secure-boot posture in examples/schema guidance.
- Weak:
  - Default strict-profile redaction posture docs for high-risk identifiers.
  - Synthetic large-fleet benchmark evidence for `report`/`history`/`drift`.
- Parity:
  - Config defaults for `db`, `report.*`, and `evidence_export.*` are now available.
  - Policy preflight quality gate (`policy lint`) now covers schema + semantic checks before DB mutation.
  - Assignment-aware checks/reporting, drift/history filters, and JSON/JUnit/SARIF outputs are in place.
- Differentiator:
  - Local-first evidence trust pipeline (manifest + optional signature + verify) with no hosted dependency.

## Brainstormed Candidates (Ranked 2026-02-12, Session 5)
- 1) Config defaults for repeated operator workflows (`db`, `report.*`, `evidence_export.*`). Score: impact 4, effort 3, fit 5, differentiation 2, risk 2, confidence 4. (selected)
- 2) Policy quality gate (`policy lint` with semantic checks + JSON output). Score: impact 4, effort 3, fit 5, differentiation 2, risk 2, confidence 4. (selected)
- 3) Invalid `--format` normalization and traceback suppression consistency. Score: impact 4, effort 2, fit 5, differentiation 1, risk 1, confidence 4. (selected)
- 4) JSON failure taxonomy (`code`, `message`) across machine-readable surfaces. Score: impact 4, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 5) Strict redaction defaults/trust-boundary docs for high-risk identifiers. Score: impact 3, effort 2, fit 4, differentiation 2, risk 1, confidence 4.
- 6) Linux secure-boot exporter parity and schema guidance. Score: impact 3, effort 3, fit 4, differentiation 2, risk 2, confidence 3.
- 7) Synthetic large-fleet benchmark + index tuning follow-up. Score: impact 3, effort 3, fit 3, differentiation 2, risk 2, confidence 3.
- 8) Packaging docs (Homebrew/Nix + checksum verification). Score: impact 2, effort 3, fit 3, differentiation 1, risk 1, confidence 3.

## Pending Features
- [ ] `P2` Reliability: explicit JSON failure taxonomy (`code`, `message`) for machine-readable command failures.
- [ ] `P2` Security defaults: stricter out-of-box redaction guidance for high-risk identifiers.
- [ ] `P3` Exporter parity: Linux secure-boot + additional schema guidance.
- [ ] `P3` Performance: synthetic large-fleet benchmark and tuning follow-ups.
- [ ] `P3` Packaging docs: Homebrew/Nix install + checksum verification guidance.
- [ ] `P3` Optional read-only dashboard.

## Pending Feature Check (2026-02-12, Session 5)
- Question: What features are still pending?
- Answer: JSON error taxonomy, strict redaction defaults/docs, exporter parity, benchmark/tuning follow-up, packaging docs, and optional dashboard.

## Cycle 1 Locked Work (Session 5)
- [x] Implement `policy lint` (file/directory recursive linting, semantic checks, text/json output).
- [x] Complete config-default resolution (`db`, `report.*`, `evidence_export.*`) and wire command usage.
- [x] Keep invalid `--format` output consistent with explicit bad value and exit code `2`.
- [x] Harden `make security` cache-path reliability by defaulting `pip_audit` cache to a writable location (`/tmp/pip-audit-cache`).
- [x] Update tests/docs/trackers and run local verification gates.

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
