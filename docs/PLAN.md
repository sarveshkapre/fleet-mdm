# FleetMDM — PLAN

## Goal
Ship a local-first, single-tenant FleetMDM controller that can ingest device inventory, manage policies/scripts metadata, and produce compliance reports without requiring authentication or networked agents.

## Scope
### MVP (v0.1.0)
- Local SQLite data store (file path configurable)
- Inventory ingest from JSON device reports
- Policy definitions in YAML with a small rules DSL
- Compliance evaluation and reports (table/JSON/CSV)
- Script catalog (store/attach metadata only; no remote execution)
- CLI-first UX with clear help and examples

### Non-goals (MVP)
- Remote agent execution or real MDM enrollment
- Multi-tenant or user accounts
- Device command execution or patching
- Network services / hosted UI

## Stack
- Language: Python 3.12
- CLI: Typer
- Data store: SQLite (stdlib)
- Config/serialization: YAML (PyYAML), JSON (stdlib)
- Validation: Pydantic (lightweight models)
- Lint/format: Ruff
- Typecheck: Pyright
- Tests: Pytest

## Architecture (high level)
- `fleetmdm.cli`: Typer app and commands
- `fleetmdm.store`: SQLite schema + CRUD
- `fleetmdm.policy`: policy parsing + evaluation engine
- `fleetmdm.report`: reporting helpers (table/JSON/CSV)
- `fleetmdm.crypto`: hash helpers for scripts

## Data model (MVP)
- `devices`: device_id, hostname, os, os_version, serial, last_seen
- `device_facts`: device_id, facts_json, updated_at
- `policies`: policy_id, name, description, raw_yaml, updated_at
- `scripts`: script_id, name, sha256, content, updated_at
- `policy_assignments`: policy_id, device_id

## CLI commands (MVP)
- `init` — initialize DB
- `ingest` — ingest device JSON
- `policy add|validate|list` — manage policies
- `policy assign` — assign policy to device(s) (or tags)
- `check` — evaluate compliance
- `report` — summary report
- `script add|list` — manage scripts (metadata only)
- `export` — export inventory
- `seed` — generate sample data

## Risks & mitigations
- Policy DSL ambiguity → keep a tiny operator set + strong validation and examples
- Inventory inconsistency → normalize required fields and surface errors
- Data growth → MVP uses SQLite with indexes; document pruning

## Milestones
1) Scaffold repo + docs + CI
2) Implement data store and CLI skeleton
3) Implement policy engine + compliance reporting
4) Tests, security hardening, and docs polish

## Open questions
- Which inventory schema should be the default? (proposed below)
- Do we want optional agent sidecar later? (future roadmap)
