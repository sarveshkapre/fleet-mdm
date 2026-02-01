# FleetMDM

Local-first, single-tenant FleetMDM controller for inventory ingest, policy checks, and compliance reporting.

## Features (current)
- Ingest JSON device inventory into SQLite
- Define policies in YAML and evaluate compliance via a small rules DSL
- Generate compliance output in table/JSON/CSV
- Script catalog (metadata only; no remote execution)

## Top risks / unknowns
- Policy scoping semantics (global vs assigned-only) need to remain predictable as assignments evolve
- Inventory schema drift across teams/tools needs strong validation + clear error messages
- Data growth and report performance as device counts increase

## Commands
- Setup / dev / lint / test / build: see `docs/PROJECT.md`
- Full gate: `make check`

## Shipped this run
- Tag-based policy assignments (`policy assign --tag`)
- Assignment introspection and removal (`policy assignments`, `policy unassign`)
- Inventory JSON schema export (`schema inventory`) + stricter ingest validation

## Next to ship
- More inventory exporters + examples
- Policy targets/scoping semantics in YAML (optional)
- Inventory drift hardening (better error surfaces, import dedupe)
- Compliance history and drift tracking
