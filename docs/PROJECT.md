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
1) More agent-side exporter examples (macOS: FileVault, OS update settings; Linux: disk encryption, kernel version) plus schema validation guidance.
2) Reporting/scaling UX: add `report` and `drift` filters (`--policy`, `--device`) to reduce noise at scale.
3) Optional read-only web dashboard for inventory + compliance + evidence verification status.
