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
1) Extend evidence redaction controls beyond inventory facts (for example, policy YAML `raw_yaml` redaction).
2) Inventory ingest dedupe/upsert by `device_id` for correctness and scale.
3) Compliance pipeline integration output (for example, `report --format junit`).
