# FleetMDM

Local-first FleetMDM controller for inventory ingest, policy checks, and compliance reporting. This is a single-tenant, no-auth tool meant to run on a workstation or jump host.

## What it does (MVP)
- Ingest JSON device inventory reports
- Store inventory in SQLite
- Validate and store policy definitions (YAML)
- Evaluate compliance and generate reports
- Store script metadata (no remote execution yet)

## Quickstart
```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"

fleetmdm init
fleetmdm seed
fleetmdm check --device mac-001
fleetmdm report
```

## Agent-side exporters (examples)
See `examples/exporters/`.

## Inventory JSON schema (MVP)
```json
{
  "device_id": "mac-001",
  "hostname": "studio-1",
  "os": "macos",
  "os_version": "14.4",
  "serial": "C02XYZ123",
  "last_seen": "2026-02-01T15:30:00Z",
  "facts": {
    "disk": { "encrypted": true },
    "cpu": { "cores": 8 },
    "tags": ["prod", "design"]
  }
}
```

## Policy YAML schema (MVP)
```yaml
id: disk-encryption
name: Disk Encryption Enabled
description: Devices must have FileVault/LUKS enabled
targets:
  os: macos
  tags: [prod, design]
checks:
  - key: disk.encrypted
    op: eq
    value: true
```

Supported operators: `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `in`, `not_in`, `regex`, `version_gte`, `version_lte`.

Targets (optional):
- `os`: string or list of OS names (e.g., `macos`, `linux`)
- `tags`: string or list of tags; policy applies if any tag matches

## Example workflow
```bash
fleetmdm init
fleetmdm ingest examples/device.json
fleetmdm policy add examples/policy.yaml
fleetmdm policy assign disk-encryption --device mac-001
fleetmdm check --device mac-001
fleetmdm report --format json
fleetmdm report --format junit > report.xml
```

### Assignments
- Assign to a tag: `fleetmdm policy assign disk-encryption --tag prod`
- Inspect: `fleetmdm policy assignments --device mac-001` or `fleetmdm policy assignments --tag prod`
- Remove: `fleetmdm policy unassign disk-encryption --tag prod`

Note: if any assignments exist (device or tag), `check`/`report` evaluate only assigned policies. If no
assignments exist, all policies apply to all devices.

### Schema export
- Inventory schema: `fleetmdm schema inventory --output inventory.schema.json`
- Validate an inventory JSON file: `fleetmdm inventory validate examples/device.json`

### History
- Recent results: `fleetmdm history --device mac-001 --limit 20`
- Filter by policy: `fleetmdm history --policy disk-encryption`

### Drift
- Compare last two runs: `fleetmdm drift`

### Evidence Packs
- Export SOC-style evidence artifacts: `fleetmdm evidence export --output evidence/`
- Redaction profiles: `--redact-profile none|minimal|strict`
- Policy YAML redaction in evidence packs: `strict` redacts `raw_yaml`; `minimal` strips comment-only lines.
- Additional facts redaction: `--redact-config ./redact.yml` (YAML/JSON allowlist/denylist for `facts.*`)
- Optional manifest signing: `--signing-key-file ./evidence.key`
- Generate a new signing key: `fleetmdm evidence keygen --keyring-dir ./keys`
- List keyring keys (from `keys/keyring.json`): `fleetmdm evidence key list --keyring-dir ./keys`
- Revoke a key (metadata only; does not delete key material): `fleetmdm evidence key revoke <key_id> --keyring-dir ./keys`
- Verify a bundle: `fleetmdm evidence verify evidence/ --signing-key-file ./evidence.key`
- Verify with rotated keys: `fleetmdm evidence verify evidence/ --keyring-dir ./keys`
- Machine-readable verification: `fleetmdm evidence verify evidence/ --format json`
- Write machine-readable verification to a file: `fleetmdm evidence verify evidence/ --keyring-dir ./keys --format json --output verify.json`
- Bundle includes: `metadata.json`, `inventory.json`, `policies.json`, `assignments.json`, `latest_run.json`, `drift.json`, `manifest.json` and optional `signature.json`

Example `redact.yml`:
```yaml
facts_denylist:
  - cpu.brand
  - disk.serial
facts_allowlist:
  - disk.encrypted
  - cpu.cores
```

## Docker
```bash
docker build -t fleetmdm .
docker run --rm -it -v $PWD/data:/data fleetmdm --db /data/fleet.db init
```

## Security notes
- Local-only MVP, no remote agent control
- Inputs validated with strict schemas
- No secrets should be stored in the repo or DB

## License
MIT
