# Project

## Setup
```bash
make setup
```

## Dev
```bash
make dev
```

## Tests
```bash
make test
```

## Lint
```bash
make lint
```

## Typecheck
```bash
make typecheck
```

## Build
```bash
make build
```

## Release
```bash
make release
```

## Next 3 improvements
1) Drift UX: optionally include “new”/“missing” rows (policy/device present in one run but not the other) behind a flag.
2) SARIF quality: optionally emit per-device failures (bounded) and include richer SARIF rule metadata (descriptions, help URIs).
3) Reporting UX for scale: add `report --only-assigned` (optional) to force “assigned-only” evaluation for big fleets.
