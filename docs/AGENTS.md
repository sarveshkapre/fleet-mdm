# AGENTS

## Working agreements
- Keep the CLI fast, local-first, and single-tenant (no auth).
- Prefer small, composable modules (`store`, `policy`, `report`, `cli`).
- Update `docs/CHANGELOG.md` for user-facing changes.

## Commands
- Setup: `make setup`
- Lint: `make lint`
- Typecheck: `make typecheck`
- Test: `make test`
- Build: `make build`
- Security: `make security`
- Full gate: `make check`

## Conventions
- Python 3.12 only
- Use type hints on public functions
- Keep policy operator behavior stable
