from pathlib import Path

from fleetmdm.store import connect, export_inventory, ingest_devices, init_db


def test_ingest_and_export(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)
    devices = [
        {
            "device_id": "mac-001",
            "hostname": "studio-1",
            "os": "macos",
            "os_version": "14.4",
            "serial": "C02XYZ123",
            "last_seen": "2026-02-01T15:30:00Z",
            "facts": {"disk": {"encrypted": True}},
        }
    ]
    with connect(db_path) as conn:
        ingest_devices(conn, devices)
        exported = export_inventory(conn)

    assert exported[0]["device_id"] == "mac-001"
    assert exported[0]["facts"]["disk"]["encrypted"] is True
