# Project

## Setup
```bash
make setup
```

## Dev
```bash
make dev
```

## Smoke
```bash
make smoke
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
1) SARIF quality: optionally emit per-device failures (bounded) and include richer SARIF rule metadata (descriptions, help URIs).
2) Evidence packs: optionally include bounded `fleetmdm history` excerpts for audit trails.
3) `fleetmdm doctor` enhancements: optional integrity checks and maintenance guidance (`VACUUM`/freelist actionability).
