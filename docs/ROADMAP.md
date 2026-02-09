# Roadmap

## Near term
- Add `history`/`drift` filters: `--since` (timestamp) and `--policy` for drift to reduce noise at scale.
- Add `report --format sarif` as an alternative compliance pipeline output.
- SQLite performance hardening: add indexes for history/results query paths and a `fleetmdm doctor` command to surface DB stats and common misconfigurations.

## Later
- Optional read-only web dashboard
- Agent sidecar for scheduled inventory uploads
- Script execution via signed bundles
