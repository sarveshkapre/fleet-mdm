# Exporters

These are sample, local-only “agent-side” exporters that emit FleetMDM inventory JSON.

Tip: validate exporter output before ingesting:
```bash
python3 examples/exporters/macos_inventory.py > device.json
fleetmdm inventory validate device.json
fleetmdm ingest device.json
```

## macOS
```bash
python3 examples/exporters/macos_inventory.py > device.json
fleetmdm inventory validate device.json
fleetmdm ingest device.json
```

Includes best-effort facts:
- `disk.encrypted` (FileVault via `fdesetup status`)
- `updates.*` (Software Update preferences from `/Library/Preferences/com.apple.SoftwareUpdate` when present)

## Linux
```bash
python3 examples/exporters/linux_inventory.py > device.json
fleetmdm inventory validate device.json
fleetmdm ingest device.json
```

Includes best-effort facts:
- `kernel.release` (from `uname`)
- `disk.encrypted` (heuristic: root filesystem mounted from a `crypt` device)

## Tags
Provide tags via `--tags` (comma-separated) or `FLEETMDM_TAGS`.

Example:
```bash
FLEETMDM_TAGS="prod,design" python3 examples/exporters/macos_inventory.py > device.json
```
