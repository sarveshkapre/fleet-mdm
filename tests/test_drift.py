from pathlib import Path
from textwrap import dedent

from fleetmdm.policy import load_policy
from fleetmdm.store import (
    add_compliance_result,
    add_policy,
    connect,
    create_compliance_run,
    ingest_devices,
    init_db,
    list_recent_runs,
    list_results_for_run,
)


def test_drift_between_runs(tmp_path: Path) -> None:
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
    policy = load_policy(policy_yaml)
    device = {
        "device_id": "mac-001",
        "hostname": "studio-1",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ123",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}},
    }

    with connect(db_path) as conn:
        ingest_devices(conn, [device])
        add_policy(conn, policy.id, policy.name, policy.description, policy_yaml)

        run1 = create_compliance_run(conn)
        add_compliance_result(
            conn,
            run1,
            device["device_id"],
            policy.id,
            policy.name,
            "pass",
            "",
        )
        run2 = create_compliance_run(conn)
        add_compliance_result(
            conn,
            run2,
            device["device_id"],
            policy.id,
            policy.name,
            "fail",
            "disk.encrypted",
        )

        runs = list_recent_runs(conn, 2)
        latest = list_results_for_run(conn, runs[0]["run_id"])
        previous = list_results_for_run(conn, runs[1]["run_id"])

    assert latest[0]["status"] == "fail"
    assert previous[0]["status"] == "pass"
