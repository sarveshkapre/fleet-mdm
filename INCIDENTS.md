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
