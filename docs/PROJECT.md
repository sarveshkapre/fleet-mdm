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
1) Add `history`/`drift` filters: `--since` and drift `--policy` for scale.
2) Add compliance pipeline integration outputs beyond JUnit (for example, `report --format sarif`).
3) SQLite performance hardening: indexes + `fleetmdm doctor` for DB stats and misconfiguration checks.
