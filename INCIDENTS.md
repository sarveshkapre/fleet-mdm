# Incidents

## 2026-02-12 - Local Regression During Maintenance: Partial CLI Helper State
- Summary:
  In-progress local edits briefly left `src/fleetmdm/cli.py` in a partially inconsistent helper/command state, causing transient command and test failures.
- Impact:
  Local validation failed until the helper definitions and `policy lint` wiring were made coherent; issue was contained before final push.
- Root Cause:
  Large incremental edits to shared CLI helpers were applied without immediately re-running full gates after each structural change.
- Detection:
  Local `make lint`/`pytest` failures and a transient `policy lint` command mismatch.
- Prevention Rules:
  After touching shared CLI helper sections, run `make lint` and targeted command smoke immediately.
  Keep helper and command-registration changes in small, atomic commits.
- Status:
  Fixed locally; `make lint`, `make typecheck`, `.venv/bin/python -m pytest -q`, and focused smoke checks pass.

## 2026-02-12 - Local Security Gate Failure: `pip_audit` Cache Path Permissions
- Summary:
  `make security` failed locally because `pip_audit` attempted to use a default cache path that is not writable in this sandboxed environment.
- Impact:
  Security gate failed before vulnerability evaluation, which obscured actionable security status and required manual workaround commands.
- Root Cause:
  Makefile invoked `pip_audit` without an explicit cache directory; tool-level defaults pointed at a permission-restricted path.
- Detection:
  Local `make security` failure with `PermissionError: [Errno 1] Operation not permitted` under `~/.pip-audit-cache`.
- Prevention Rules:
  Keep security-tool cache paths explicit and writable in automation targets.
  Parameterize cache locations with an override variable for CI/sandbox portability.
- Status:
  Fixed on `main` by setting `PIP_AUDIT_CACHE_DIR` default in `Makefile` and using `pip_audit --cache-dir $(PIP_AUDIT_CACHE_DIR)`.

## 2026-02-09 - Local Smoke Failure: `make dev` Used Non-Executable Package Module
- Summary:
  Local smoke verification failed because `make dev` ran `python -m fleetmdm`, but the package has no `__main__`.
- Impact:
  `make dev` (documented in `docs/PROJECT.md`) was broken on a fresh environment; this increases friction for new contributors and automation smoke paths.
- Root Cause:
  Makefile assumed package-module execution (`python -m fleetmdm`) instead of the supported entrypoints (`fleetmdm` console script / `python -m fleetmdm.cli`).
- Detection:
  Local smoke run error: `No module named fleetmdm.__main__`.
- Prevention Rules:
  Keep `make dev` as a real smoke target and include it in manual smoke verification.
  For Typer CLIs, prefer `python -m <package>.cli` (or the console script) unless a `__main__.py` is explicitly added and tested.
- Status:
  Fixed on `main` by switching `make dev` to `python -m fleetmdm.cli --help`.

## 2026-02-09 - Local Security Gate Failure: Bandit B608 on Dynamic SQL Assembly
- Summary:
  `make security` failed after introducing a dynamically constructed SQL query in `list_results_for_run` (Bandit B608).
- Impact:
  Would have caused CI `security` job failures if pushed; caught before release.
- Root Cause:
  Query string was assembled using string formatting, triggering Bandit’s SQL injection heuristic even though parameters were bound.
- Detection:
  Local `make security` failure with B608 pointing at `src/fleetmdm/store.py`.
- Prevention Rules:
  Avoid string-built SQL in security-gated code paths; use explicit static query variants with bound parameters.
  Run `make security` before pushing changes that touch SQL/query code.
- Status:
  Refactored to explicit query branches; `make security` passes.

## 2026-02-09 - Historical CI Environment Parity Failure
- Summary:
  Multiple GitHub Actions runs failed because `make` invoked `.venv/bin/python` while CI dependencies were installed into system Python on those commits.
- Impact:
  `check` and `security` jobs failed even when application code was otherwise valid.
- Root Cause:
  Tooling path assumptions were inconsistent between local workflow and CI setup.
- Detection:
  GitHub Actions failures (`No module named ruff`, `No module named pip_audit`) on runs tied to older commits.
- Prevention Rules:
  Keep one canonical setup path (`make setup`) for both local and CI; avoid direct hardcoding of interpreter paths that bypass environment setup.
  Verify workflow commands consume the same dependency environment before merging.
- Status:
  Mitigated on `main`; keep monitoring new workflow changes for parity regressions.

## 2026-02-09 - CI Secrets Scan Failure Due To gitleaks-action License Requirement
- Summary:
  The `secrets` GitHub Actions job failed because `gitleaks/gitleaks-action@v2` began enforcing a license key in this environment.
- Impact:
  CI was red on pushes even though the code and tests were passing.
- Root Cause:
  Dependency on an action that introduced an external license requirement and also hit unauthenticated GitHub API rate limits.
- Detection:
  GitHub Actions log error: "missing gitleaks license" (run `21814144161`).
- Prevention Rules:
  Prefer OSS tooling invocation (pinned binaries with checksum verification) over actions that can change licensing behavior.
  Pin versions and verify downloads with checksums for security-sensitive CI steps.
- Status:
  Mitigated by replacing the action with a pinned gitleaks CLI install and running `gitleaks detect`.

## 2026-02-09 - CI Security Gate Failure After Adding JUnit XML Output
- Summary:
  The GitHub Actions `security` job failed after adding JUnit XML output because Bandit flags `xml.etree.ElementTree` imports (B405) even when used only for XML generation.
- Impact:
  `main` briefly had failing CI runs on commits that introduced the JUnit renderer.
- Root Cause:
  Bandit blacklist heuristic (B405) on `xml.etree` imports; the implementation used ElementTree for serialization, not parsing.
- Detection:
  `make security` / GitHub Actions `security` job failure.
- Prevention Rules:
  Run `make security` before pushing.
  When using a blacklisted module for safe-only usage (generation not parsing), document and suppress with a targeted `# nosec` + justification; otherwise prefer string rendering or a hardened XML library if parsing is needed.
- Notes:
  2026-02-10: Bandit in CI did not honor `# nosec B405` on the import line in this repo; prefer plain `# nosec` for B405 suppressions.
- Status:
  Mitigated on `main` (commit `3851144`).

### 2026-02-12T20:00:44Z | Codex execution failure
- Date: 2026-02-12T20:00:44Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-2.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:04:01Z | Codex execution failure
- Date: 2026-02-12T20:04:01Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-3.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:07:30Z | Codex execution failure
- Date: 2026-02-12T20:07:30Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-4.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:10:58Z | Codex execution failure
- Date: 2026-02-12T20:10:58Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-5.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:14:30Z | Codex execution failure
- Date: 2026-02-12T20:14:30Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-6.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:17:58Z | Codex execution failure
- Date: 2026-02-12T20:17:58Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-7.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:21:26Z | Codex execution failure
- Date: 2026-02-12T20:21:26Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-8.log
- Commit: pending
- Confidence: medium

### 2026-02-12T20:24:52Z | Codex execution failure
- Date: 2026-02-12T20:24:52Z
- Trigger: Codex execution failure
- Impact: Repo session did not complete cleanly
- Root Cause: codex exec returned a non-zero status
- Fix: Captured failure logs and kept repository in a recoverable state
- Prevention Rule: Re-run with same pass context and inspect pass log before retrying
- Evidence: pass_log=logs/20260212-101456-fleet-mdm-cycle-9.log
- Commit: pending
- Confidence: medium
