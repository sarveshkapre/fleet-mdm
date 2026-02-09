# Incidents

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
- Status:
  Mitigated on `main` (commit `3851144`).
