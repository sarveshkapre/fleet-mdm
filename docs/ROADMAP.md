# Roadmap

## Near term
- SARIF quality: optionally emit per-device failures (with a cap) and include richer SARIF rule metadata (descriptions, help URIs).
- Evidence packs: optionally include bounded `fleetmdm history` excerpts in evidence bundles for audit trails.
- More agent-side exporter examples beyond the current macOS/Linux baseline (macOS: firewall, OS update deferrals; Linux: secure boot, disk layout) plus schema validation guidance.
- Optional read-only web dashboard for inventory + compliance + evidence verification status.

## Later
- Optional read-only web dashboard
- Agent sidecar for scheduled inventory uploads
- Script execution via signed bundles
