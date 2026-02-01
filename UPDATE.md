# Update (2026-02-01)

## Shipped
- Policy assignments now support tags and can be inspected/removed:
  - `fleetmdm policy assign <policy_id> --tag <tag>`
  - `fleetmdm policy assignments --device <device_id>`
  - `fleetmdm policy assignments --tag <tag>`
  - `fleetmdm policy unassign <policy_id> --device <device_id>`
  - `fleetmdm policy unassign <policy_id> --tag <tag>`
- Inventory ingest now uses a strict schema, and you can export the JSON schema:
  - `fleetmdm schema inventory --output inventory.schema.json`
- Sample “agent-side” exporters for macOS/Linux:
  - `python3 examples/exporters/macos_inventory.py > device.json`
  - `python3 examples/exporters/linux_inventory.py > device.json`
  - `fleetmdm inventory validate device.json`
- Compliance history is now recorded on every `check`, with a CLI viewer:
  - `fleetmdm history --device <device_id>`
  - `fleetmdm history --policy <policy_id> --limit 20`
- Drift report compares the last two runs:
  - `fleetmdm drift`
- Policy YAML now supports `targets` (OS/tags) to scope applicability.

## Notes
- When any assignments exist (device or tag), `check` and `report` evaluate only assigned policies; if no
  assignments exist, all policies apply to all devices.

## Commands
- Gate: `make check`

## PR
- Per request, no PR was created; changes are ready to commit directly on `main`.
