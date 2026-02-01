from pathlib import Path
from textwrap import dedent

from fleetmdm.store import (
    add_policy,
    assign_policy,
    assign_policy_to_tag,
    connect,
    has_any_policy_assignments,
    ingest_devices,
    init_db,
    list_policy_assignments_for_tag,
    resolve_assigned_policies_for_device,
    unassign_policy,
    unassign_policy_from_tag,
)


def test_policy_assignments_by_device_and_tag(tmp_path: Path) -> None:
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
            "facts": {"disk": {"encrypted": True}, "tags": ["prod", "design"]},
        },
        {
            "device_id": "linux-001",
            "hostname": "render-1",
            "os": "linux",
            "os_version": "22.04",
            "serial": "LINUX123",
            "last_seen": "2026-02-01T15:30:00Z",
            "facts": {"disk": {"encrypted": False}, "tags": ["dev"]},
        },
    ]

    with connect(db_path) as conn:
        ingest_devices(conn, devices)
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, policy_yaml_1)
        add_policy(conn, "cpu-min", "CPU Minimum", None, policy_yaml_2)

        assert has_any_policy_assignments(conn) is False

        assign_policy_to_tag(conn, "disk-encryption", "prod")
        assign_policy(conn, "cpu-min", "mac-001")

        assert has_any_policy_assignments(conn) is True
        assert list_policy_assignments_for_tag(conn, "prod") == ["disk-encryption"]

        mac_policies = resolve_assigned_policies_for_device(conn, "mac-001", ["prod"])
        linux_policies = resolve_assigned_policies_for_device(conn, "linux-001", ["dev"])

        assert unassign_policy(conn, "cpu-min", "mac-001") == 1
        assert unassign_policy(conn, "cpu-min", "mac-001") == 0
        assert unassign_policy_from_tag(conn, "disk-encryption", "prod") == 1
        assert unassign_policy_from_tag(conn, "disk-encryption", "prod") == 0

    assert mac_policies == ["cpu-min", "disk-encryption"]
    assert linux_policies == []
