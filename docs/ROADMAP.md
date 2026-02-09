# Roadmap

## Near term
- Reporting UX for scale: add `report --only-failing` / `--only-skipped` (and maybe `--only-assigned`) to reduce noise.
- Drift UX: optionally include “new”/“missing” rows (policy/device present in one run but not the other) behind a flag.
- More agent-side exporter examples beyond the current macOS/Linux baseline (macOS: firewall, OS update deferrals; Linux: secure boot, disk layout) plus schema validation guidance.
- Optional read-only web dashboard for inventory + compliance + evidence verification status.

## Later
- Optional read-only web dashboard
- Agent sidecar for scheduled inventory uploads
- Script execution via signed bundles
