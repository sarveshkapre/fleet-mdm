from pathlib import Path
from textwrap import dedent

from fleetmdm.store import (
    add_compliance_result,
    add_policy,
    assign_policy_to_tag,
    connect,
    create_compliance_run,
    export_inventory,
    get_tag_assigned_policies,
    ingest_devices,
    init_db,
    list_compliance_history,
)


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


def test_get_tag_assigned_policies_deduplicates_tags(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    policy_yaml = dedent(
        """
        id: disk-encryption
        name: Disk Encryption Enabled
        checks:
          - key: disk.encrypted
            op: eq
            value: true
        """
    ).strip()

    with connect(db_path) as conn:
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, policy_yaml)
        assign_policy_to_tag(conn, "disk-encryption", "prod")
        result = get_tag_assigned_policies(conn, ["prod", "prod", "", "design"])

    assert result == ["disk-encryption"]


def test_list_compliance_history_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    policy_yaml_1 = dedent(
        """
        id: disk-encryption
        name: Disk Encryption Enabled
        checks:
          - key: disk.encrypted
            op: eq
            value: true
        """
    ).strip()
    policy_yaml_2 = dedent(
        """
        id: cpu-min
        name: CPU Minimum
        checks:
          - key: cpu.cores
            op: gte
            value: 8
        """
    ).strip()

    devices = [
        {
            "device_id": "mac-001",
            "hostname": "studio-1",
            "os": "macos",
            "os_version": "14.4",
            "serial": "C02XYZ123",
            "last_seen": "2026-02-01T15:30:00Z",
            "facts": {"disk": {"encrypted": True}, "cpu": {"cores": 8}},
        },
        {
            "device_id": "linux-001",
            "hostname": "render-1",
            "os": "linux",
            "os_version": "22.04",
            "serial": "LINUX123",
            "last_seen": "2026-02-01T15:30:00Z",
            "facts": {"disk": {"encrypted": False}, "cpu": {"cores": 16}},
        },
    ]

    with connect(db_path) as conn:
        ingest_devices(conn, devices)
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, policy_yaml_1)
        add_policy(conn, "cpu-min", "CPU Minimum", None, policy_yaml_2)
        run_id = create_compliance_run(conn)
        add_compliance_result(
            conn, run_id, "mac-001", "disk-encryption", "Disk Encryption Enabled", "pass", ""
        )
        add_compliance_result(conn, run_id, "mac-001", "cpu-min", "CPU Minimum", "pass", "")
        add_compliance_result(
            conn,
            run_id,
            "linux-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "fail",
            "disk.encrypted",
        )

        all_rows = list_compliance_history(conn, None, None, 50)
        device_rows = list_compliance_history(conn, "mac-001", None, 50)
        policy_rows = list_compliance_history(conn, None, "disk-encryption", 50)
        device_policy_rows = list_compliance_history(conn, "mac-001", "disk-encryption", 50)

    assert len(all_rows) == 3
    assert len(device_rows) == 2
    assert all(str(row["device_id"]) == "mac-001" for row in device_rows)
    assert len(policy_rows) == 2
    assert all(str(row["policy_id"]) == "disk-encryption" for row in policy_rows)
    assert len(device_policy_rows) == 1
    assert str(device_policy_rows[0]["device_id"]) == "mac-001"
    assert str(device_policy_rows[0]["policy_id"]) == "disk-encryption"
