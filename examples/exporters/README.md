# Exporters

These are sample, local-only “agent-side” exporters that emit FleetMDM inventory JSON.

## macOS
```bash
python3 examples/exporters/macos_inventory.py > device.json
fleetmdm inventory validate device.json
fleetmdm ingest device.json
```

## Linux
```bash
python3 examples/exporters/linux_inventory.py > device.json
fleetmdm inventory validate device.json
fleetmdm ingest device.json
```

## Tags
Provide tags via `--tags` (comma-separated) or `FLEETMDM_TAGS`.

Example:
```bash
FLEETMDM_TAGS="prod,design" python3 examples/exporters/macos_inventory.py > device.json
```

