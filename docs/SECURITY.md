# Security

## Reporting
Please open a GitHub issue for non-sensitive bugs. For sensitive reports, contact the maintainer directly.

## Threat model (MVP)
- Local-only execution; no remote agents or server endpoints
- Input validation on JSON and YAML payloads
- SQLite file is local and not encrypted by default

## Recommendations
- Store the DB on encrypted volumes if it contains sensitive metadata
- Keep policy files in version control to track changes
