import csv
import json
import subprocess
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from typer.testing import CliRunner

from fleetmdm.cli import app
from fleetmdm.store import (
    add_compliance_result,
    add_policy,
    connect,
    create_compliance_run,
    ingest_devices,
    init_db,
)

runner = CliRunner()


def test_python_module_entrypoints_show_help() -> None:
    # These smoke the `python -m` entrypoints that people use in Makefiles/CI.
    for module in ("fleetmdm", "fleetmdm.cli"):
        proc = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert (proc.stdout + proc.stderr).strip()


def test_script_list_initializes_database(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    result = runner.invoke(app, ["script", "list", "--db", str(db_path)])
    assert result.exit_code == 0
    assert db_path.exists()


def test_evidence_export_writes_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence"

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    check_result = runner.invoke(
        app, ["check", "--device", "mac-001", "--db", str(db_path), "--format", "json"]
    )
    assert check_result.exit_code == 0
    payload = json.loads(check_result.stdout)
    assert payload[0]["results"][0]["passed"] is True

    result = runner.invoke(
        app, ["evidence", "export", "--db", str(db_path), "--output", str(output_dir)]
    )
    assert result.exit_code == 0

    for filename in [
        "metadata.json",
        "inventory.json",
        "policies.json",
        "assignments.json",
        "latest_run.json",
        "drift.json",
        "manifest.json",
    ]:
        assert (output_dir / filename).exists()

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    latest_run = json.loads((output_dir / "latest_run.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert metadata["schema_version"] == 1
    assert latest_run["run_id"].startswith("run-")
    assert manifest["artifact_count"] == 6

    verify = runner.invoke(app, ["evidence", "verify", str(output_dir)])
    assert verify.exit_code == 0


def test_evidence_export_strict_redaction_profile(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-strict"

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    result = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--redact-profile",
            "strict",
        ],
    )
    assert result.exit_code == 0

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    inventory = json.loads((output_dir / "inventory.json").read_text(encoding="utf-8"))
    latest_run = json.loads((output_dir / "latest_run.json").read_text(encoding="utf-8"))
    policies = json.loads((output_dir / "policies.json").read_text(encoding="utf-8"))

    assert metadata["redaction_profile"] == "strict"
    assert metadata["policies_raw_yaml"] == "redacted"
    assert all(entry["device_id"].startswith("device-") for entry in inventory)
    assert all(entry["serial"].startswith("serial-") for entry in inventory)
    assert latest_run["results"][0]["device_id"].startswith("device-")
    assert all(policy["raw_yaml"] is None for policy in policies)
    assert all(policy["raw_yaml_redacted"] is True for policy in policies)


def test_evidence_export_minimal_strips_policy_comment_lines(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-minimal"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "# top comment should be stripped",
                "id: disk-encryption",
                "name: Disk Encryption Enabled",
                "description: test policy",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    export = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--redact-profile",
            "minimal",
        ],
    )
    assert export.exit_code == 0

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    policies = json.loads((output_dir / "policies.json").read_text(encoding="utf-8"))
    assert metadata["redaction_profile"] == "minimal"
    assert metadata["policies_raw_yaml"] == "comment_stripped"

    disk_policy = next(item for item in policies if item["policy_id"] == "disk-encryption")
    assert disk_policy["raw_yaml_redacted"] is False
    assert "# top comment" not in disk_policy["raw_yaml"]


def test_evidence_export_sign_and_verify_detects_tamper(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-signed"
    key_path = tmp_path / "signing.key"

    key_path.write_text("super-secret-signing-key", encoding="utf-8")

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    result = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert result.exit_code == 0
    assert (output_dir / "signature.json").exists()

    verify = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert verify.exit_code == 0

    inventory_path = output_dir / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory[0]["hostname"] = "tampered-host"
    inventory_path.write_text(f"{json.dumps(inventory, indent=2)}\n", encoding="utf-8")

    failed_verify = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert failed_verify.exit_code == 1
    assert "Checksum mismatch: inventory.json" in failed_verify.stdout


def test_evidence_verify_requires_signature_when_key_provided(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-unsigned"
    key_path = tmp_path / "signing.key"

    key_path.write_text("super-secret-signing-key", encoding="utf-8")
    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0

    export = runner.invoke(
        app,
        ["evidence", "export", "--db", str(db_path), "--output", str(output_dir)],
    )
    assert export.exit_code == 0

    verify = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert verify.exit_code == 1
    assert "signature.json not found" in verify.stdout


def test_evidence_keyring_verify_and_json_report(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-keyring"
    keyring_dir = tmp_path / "keys"
    keyring_dir.mkdir(parents=True, exist_ok=True)

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    keygen = runner.invoke(app, ["evidence", "keygen", "--keyring-dir", str(keyring_dir)])
    assert keygen.exit_code == 0
    key_files = sorted([p for p in keyring_dir.iterdir() if p.is_file()])
    # key file + keyring.json manifest
    assert any(p.name == "keyring.json" for p in key_files)
    key_paths = sorted([p for p in key_files if p.suffix == ".key"])
    assert len(key_paths) == 1
    manifest = json.loads((keyring_dir / "keyring.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert len(manifest["keys"]) == 1
    assert manifest["keys"][0]["status"] == "active"

    export = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--signing-key-file",
            str(key_paths[0]),
        ],
    )
    assert export.exit_code == 0

    verify = runner.invoke(
        app, ["evidence", "verify", str(output_dir), "--keyring-dir", str(keyring_dir)]
    )
    assert verify.exit_code == 0

    report_path = tmp_path / "verify.json"
    verify_json = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--keyring-dir",
            str(keyring_dir),
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )
    assert verify_json.exit_code == 0
    assert verify_json.stdout.strip() == ""
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["signature"]["present"] is True
    assert payload["signature"]["verified"] is True
    assert payload["signature"]["key_id"]
    assert payload["signature"]["signed_at"]

    empty_keyring = tmp_path / "keys-empty"
    empty_keyring.mkdir(parents=True, exist_ok=True)
    failed_verify = runner.invoke(
        app, ["evidence", "verify", str(output_dir), "--keyring-dir", str(empty_keyring)]
    )
    assert failed_verify.exit_code == 1
    assert "No key found in keyring" in failed_verify.stdout


def test_evidence_key_revoke_marks_key_revoked_and_verify_warns(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-revoked"
    keyring_dir = tmp_path / "keys"
    keyring_dir.mkdir(parents=True, exist_ok=True)

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    keygen = runner.invoke(app, ["evidence", "keygen", "--keyring-dir", str(keyring_dir)])
    assert keygen.exit_code == 0
    manifest = json.loads((keyring_dir / "keyring.json").read_text(encoding="utf-8"))
    key_id = manifest["keys"][0]["key_id"]
    key_path = keyring_dir / manifest["keys"][0]["filename"]

    export = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert export.exit_code == 0

    time.sleep(0.01)
    revoke = runner.invoke(
        app,
        ["evidence", "key", "revoke", key_id, "--keyring-dir", str(keyring_dir)],
    )
    assert revoke.exit_code == 0

    verify_json = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--keyring-dir",
            str(keyring_dir),
            "--format",
            "json",
        ],
    )
    assert verify_json.exit_code == 0
    payload = json.loads(verify_json.stdout)
    assert payload["ok"] is True
    assert payload["signature"]["verified"] is True
    assert payload["signature"]["key_status"] == "revoked"
    assert payload["signature"]["lifecycle_ok"] is True
    assert payload["signature"]["lifecycle_warnings"]


def test_evidence_verify_fails_if_signature_after_key_revocation(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-after-revoke"
    keyring_dir = tmp_path / "keys"
    keyring_dir.mkdir(parents=True, exist_ok=True)

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    keygen = runner.invoke(app, ["evidence", "keygen", "--keyring-dir", str(keyring_dir)])
    assert keygen.exit_code == 0
    manifest = json.loads((keyring_dir / "keyring.json").read_text(encoding="utf-8"))
    key_id = manifest["keys"][0]["key_id"]
    key_path = keyring_dir / manifest["keys"][0]["filename"]

    revoke = runner.invoke(
        app,
        ["evidence", "key", "revoke", key_id, "--keyring-dir", str(keyring_dir)],
    )
    assert revoke.exit_code == 0

    time.sleep(0.01)
    export = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--signing-key-file",
            str(key_path),
        ],
    )
    assert export.exit_code == 0

    verify = runner.invoke(
        app,
        [
            "evidence",
            "verify",
            str(output_dir),
            "--keyring-dir",
            str(keyring_dir),
            "--format",
            "json",
        ],
    )
    assert verify.exit_code == 1
    payload = json.loads(verify.stdout)
    assert payload["signature"]["verified"] is True
    assert "after key revocation" in "\n".join(payload["errors"]).lower()


def test_evidence_export_redact_config_applies_to_facts(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    output_dir = tmp_path / "evidence-redact-config"
    config_path = tmp_path / "redact.yml"

    config_path.write_text(
        "\n".join(
            [
                "facts_allowlist:",
                "  - disk.encrypted",
                "  - cpu.cores",
                "facts_denylist:",
                "  - cpu.cores",
                "replacement: \"[REDACTED]\"",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["check", "--device", "mac-001", "--db", str(db_path)]).exit_code == 0
    )

    export = runner.invoke(
        app,
        [
            "evidence",
            "export",
            "--db",
            str(db_path),
            "--output",
            str(output_dir),
            "--redact-config",
            str(config_path),
        ],
    )
    assert export.exit_code == 0

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    inventory = json.loads((output_dir / "inventory.json").read_text(encoding="utf-8"))
    assert metadata["facts_redaction"]["facts_allowlist"] == ["cpu.cores", "disk.encrypted"]
    assert metadata["facts_redaction"]["facts_denylist"] == ["cpu.cores"]

    mac = next(item for item in inventory if item["device_id"] == "mac-001")
    assert mac["facts"]["disk"]["encrypted"] is True
    assert mac["facts"]["cpu"]["cores"] == "[REDACTED]"


def test_report_junit_format_emits_failures(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: disk-encryption",
                "name: Disk Encryption Enabled",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(app, ["report", "--db", str(db_path), "--format", "junit"])
    assert result.exit_code == 0

    root = ET.fromstring(result.stdout)
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "1"

    cases = root.findall("testcase")
    assert any(case.attrib.get("name") == "disk-encryption" for case in cases)
    failing = [case for case in cases if case.attrib.get("name") == "disk-encryption"]
    assert failing
    assert failing[0].find("failure") is not None


def test_report_sarif_format_emits_results(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: disk-encryption",
                "name: Disk Encryption Enabled",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(app, ["report", "--db", str(db_path), "--format", "sarif"])
    assert result.exit_code == 0

    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif and sarif["runs"]
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "FleetMDM"
    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "disk-encryption"


def test_report_policy_filter_limits_output(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: disk-encryption",
                "name: Disk Encryption Enabled",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(
        app,
        ["report", "--db", str(db_path), "--format", "json", "--policy", "disk-encryption"],
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert len(rows) == 1
    assert rows[0]["policy_id"] == "disk-encryption"


def test_report_csv_quotes_and_sanitizes_cells(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: \"=evil\"",
                "name: \"Comma, Name\"",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(app, ["report", "--db", str(db_path), "--format", "csv"])
    assert result.exit_code == 0

    rows = list(csv.reader(result.stdout.splitlines()))
    header = rows[0]
    assert header == ["policy_id", "policy_name", "passed", "failed"]

    evil = next(r for r in rows[1:] if r[0] == "'=evil")
    assert evil[1] == "Comma, Name"


def test_report_only_failing_filters_output(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: disk-encryption",
                "name: Disk Encryption Enabled",
                "checks:",
                "  - key: disk.encrypted",
                "    op: eq",
                "    value: true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(
        app, ["report", "--db", str(db_path), "--format", "json", "--only-failing"]
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert len(rows) == 1
    assert rows[0]["policy_id"] == "disk-encryption"
    assert int(rows[0]["failed_count"]) > 0


def test_report_only_skipped_filters_output(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    policy_path = tmp_path / "policy.yaml"

    policy_path.write_text(
        "\n".join(
            [
                "id: windows-only",
                "name: Windows Only Policy",
                "targets:",
                "  os: windows",
                "checks:",
                "  - key: os_version",
                "    op: version_gte",
                "    value: \"1.0\"",
                "",
            ]
        ),
        encoding="utf-8",
    )

    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0
    assert (
        runner.invoke(app, ["policy", "add", str(policy_path), "--db", str(db_path)]).exit_code
        == 0
    )

    result = runner.invoke(
        app, ["report", "--db", str(db_path), "--format", "json", "--only-skipped"]
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert len(rows) == 1
    assert rows[0]["policy_id"] == "windows-only"
    assert int(rows[0]["passed_count"]) == 0
    assert int(rows[0]["failed_count"]) == 0


def test_report_only_assigned_forces_assignment_scope(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    assert runner.invoke(app, ["seed", "--db", str(db_path)]).exit_code == 0

    baseline = runner.invoke(app, ["report", "--db", str(db_path), "--format", "json"])
    assert baseline.exit_code == 0
    baseline_rows = json.loads(baseline.stdout)
    assert len(baseline_rows) == 1
    assert int(baseline_rows[0]["passed_count"]) > 0

    forced = runner.invoke(
        app, ["report", "--db", str(db_path), "--format", "json", "--only-assigned"]
    )
    assert forced.exit_code == 0
    forced_rows = json.loads(forced.stdout)
    assert len(forced_rows) == 1
    assert int(forced_rows[0]["passed_count"]) == 0
    assert int(forced_rows[0]["failed_count"]) == 0

    assigned = runner.invoke(
        app,
        [
            "policy",
            "assign",
            "min-os-version",
            "--device",
            "mac-001",
            "--db",
            str(db_path),
        ],
    )
    assert assigned.exit_code == 0

    forced_after_assign = runner.invoke(
        app, ["report", "--db", str(db_path), "--format", "json", "--only-assigned"]
    )
    assert forced_after_assign.exit_code == 0
    forced_rows_after_assign = json.loads(forced_after_assign.stdout)
    assert len(forced_rows_after_assign) == 1
    assert int(forced_rows_after_assign[0]["passed_count"]) == 1
    assert int(forced_rows_after_assign[0]["failed_count"]) == 0


def test_history_since_filters_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    device = {
        "device_id": "mac-001",
        "hostname": "studio-1",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ123",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}},
    }
    policy_yaml = "\n".join(
        [
            "id: disk-encryption",
            "name: Disk Encryption Enabled",
            "checks:",
            "  - key: disk.encrypted",
            "    op: eq",
            "    value: true",
            "",
        ]
    )

    with connect(db_path) as conn:
        ingest_devices(conn, [device])
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, policy_yaml)

        run1 = create_compliance_run(conn, started_at="2026-02-01T00:00:00Z")
        add_compliance_result(
            conn,
            run1,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "pass",
            "",
            checked_at="2026-02-01T00:00:00Z",
        )

        run2 = create_compliance_run(conn, started_at="2026-02-03T00:00:00Z")
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "fail",
            "disk.encrypted",
            checked_at="2026-02-03T00:00:00Z",
        )

    result = runner.invoke(
        app,
        [
            "history",
            "--db",
            str(db_path),
            "--format",
            "json",
            "--since",
            "2026-02-02T00:00:00Z",
        ],
    )
    assert result.exit_code == 0

    rows = json.loads(result.stdout)
    assert len(rows) == 1
    assert rows[0]["status"] == "fail"
    assert rows[0]["checked_at"].startswith("2026-02-03T00:00:00")


def test_drift_supports_since_and_policy_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    device = {
        "device_id": "mac-001",
        "hostname": "studio-1",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ123",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}, "cpu": {"cores": 8}},
    }
    disk_yaml = "\n".join(
        [
            "id: disk-encryption",
            "name: Disk Encryption Enabled",
            "checks:",
            "  - key: disk.encrypted",
            "    op: eq",
            "    value: true",
            "",
        ]
    )
    cpu_yaml = "\n".join(
        [
            "id: cpu-min",
            "name: CPU Minimum",
            "checks:",
            "  - key: cpu.cores",
            "    op: gte",
            "    value: 8",
            "",
        ]
    )

    with connect(db_path) as conn:
        ingest_devices(conn, [device])
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, disk_yaml)
        add_policy(conn, "cpu-min", "CPU Minimum", None, cpu_yaml)

        run2 = create_compliance_run(conn, started_at="2026-02-03T00:00:00Z")
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "pass",
            "",
            checked_at="2026-02-03T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "cpu-min",
            "CPU Minimum",
            "pass",
            "",
            checked_at="2026-02-03T00:00:00Z",
        )

        run3 = create_compliance_run(conn, started_at="2026-02-05T00:00:00Z")
        add_compliance_result(
            conn,
            run3,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "fail",
            "disk.encrypted",
            checked_at="2026-02-05T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run3,
            "mac-001",
            "cpu-min",
            "CPU Minimum",
            "fail",
            "cpu.cores",
            checked_at="2026-02-05T00:00:00Z",
        )

    filtered = runner.invoke(
        app,
        [
            "drift",
            "--db",
            str(db_path),
            "--format",
            "json",
            "--since",
            "2026-02-02T00:00:00Z",
            "--policy",
            "disk-encryption",
        ],
    )
    assert filtered.exit_code == 0

    rows = json.loads(filtered.stdout)
    assert len(rows) == 1
    assert rows[0]["policy_id"] == "disk-encryption"
    assert rows[0]["previous"] == "pass"
    assert rows[0]["current"] == "fail"


def test_drift_device_filter_limits_output(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    device1 = {
        "device_id": "mac-001",
        "hostname": "studio-1",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ123",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}},
    }
    device2 = {
        "device_id": "mac-002",
        "hostname": "studio-2",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ124",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}},
    }
    policy_yaml = "\n".join(
        [
            "id: disk-encryption",
            "name: Disk Encryption Enabled",
            "checks:",
            "  - key: disk.encrypted",
            "    op: eq",
            "    value: true",
            "",
        ]
    )

    with connect(db_path) as conn:
        ingest_devices(conn, [device1, device2])
        add_policy(conn, "disk-encryption", "Disk Encryption Enabled", None, policy_yaml)

        run1 = create_compliance_run(conn, started_at="2026-02-01T00:00:00Z")
        add_compliance_result(
            conn,
            run1,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "pass",
            "",
            checked_at="2026-02-01T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run1,
            "mac-002",
            "disk-encryption",
            "Disk Encryption Enabled",
            "pass",
            "",
            checked_at="2026-02-01T00:00:00Z",
        )

        run2 = create_compliance_run(conn, started_at="2026-02-03T00:00:00Z")
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "disk-encryption",
            "Disk Encryption Enabled",
            "fail",
            "disk.encrypted",
            checked_at="2026-02-03T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run2,
            "mac-002",
            "disk-encryption",
            "Disk Encryption Enabled",
            "pass",
            "",
            checked_at="2026-02-03T00:00:00Z",
        )

    result = runner.invoke(
        app,
        ["drift", "--db", str(db_path), "--format", "json", "--device", "mac-001"],
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert len(rows) == 1
    assert rows[0]["device_id"] == "mac-001"
    assert rows[0]["policy_id"] == "disk-encryption"
    assert rows[0]["previous"] == "pass"
    assert rows[0]["current"] == "fail"


def test_drift_include_new_missing_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    init_db(db_path)

    device = {
        "device_id": "mac-001",
        "hostname": "studio-1",
        "os": "macos",
        "os_version": "14.4",
        "serial": "C02XYZ123",
        "last_seen": "2026-02-01T15:30:00Z",
        "facts": {"disk": {"encrypted": True}, "cpu": {"cores": 8}},
    }
    shared_yaml = "\n".join(
        [
            "id: shared-policy",
            "name: Shared Policy",
            "checks:",
            "  - key: disk.encrypted",
            "    op: eq",
            "    value: true",
            "",
        ]
    )
    previous_only_yaml = "\n".join(
        [
            "id: previous-only",
            "name: Previous Only",
            "checks:",
            "  - key: cpu.cores",
            "    op: gte",
            "    value: 8",
            "",
        ]
    )
    latest_only_yaml = "\n".join(
        [
            "id: latest-only",
            "name: Latest Only",
            "checks:",
            "  - key: cpu.cores",
            "    op: gte",
            "    value: 12",
            "",
        ]
    )

    with connect(db_path) as conn:
        ingest_devices(conn, [device])
        add_policy(conn, "shared-policy", "Shared Policy", None, shared_yaml)
        add_policy(conn, "previous-only", "Previous Only", None, previous_only_yaml)
        add_policy(conn, "latest-only", "Latest Only", None, latest_only_yaml)

        run1 = create_compliance_run(conn, started_at="2026-02-01T00:00:00Z")
        add_compliance_result(
            conn,
            run1,
            "mac-001",
            "shared-policy",
            "Shared Policy",
            "pass",
            "",
            checked_at="2026-02-01T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run1,
            "mac-001",
            "previous-only",
            "Previous Only",
            "pass",
            "",
            checked_at="2026-02-01T00:00:00Z",
        )

        run2 = create_compliance_run(conn, started_at="2026-02-03T00:00:00Z")
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "shared-policy",
            "Shared Policy",
            "pass",
            "",
            checked_at="2026-02-03T00:00:00Z",
        )
        add_compliance_result(
            conn,
            run2,
            "mac-001",
            "latest-only",
            "Latest Only",
            "fail",
            "cpu.cores",
            checked_at="2026-02-03T00:00:00Z",
        )

    default = runner.invoke(app, ["drift", "--db", str(db_path), "--format", "json"])
    assert default.exit_code == 0
    assert json.loads(default.stdout) == []

    result = runner.invoke(
        app,
        [
            "drift",
            "--db",
            str(db_path),
            "--format",
            "json",
            "--include-new-missing",
        ],
    )
    assert result.exit_code == 0
    rows = json.loads(result.stdout)
    assert len(rows) == 2

    by_policy = {row["policy_id"]: row for row in rows}
    assert by_policy["latest-only"]["change_type"] == "new"
    assert by_policy["latest-only"]["previous"] == "missing"
    assert by_policy["latest-only"]["current"] == "fail"

    assert by_policy["previous-only"]["change_type"] == "missing"
    assert by_policy["previous-only"]["previous"] == "pass"
    assert by_policy["previous-only"]["current"] == "missing"


def test_doctor_json_includes_db_stats(tmp_path: Path) -> None:
    db_path = tmp_path / "fleet.db"
    result = runner.invoke(app, ["doctor", "--db", str(db_path), "--format", "json"])
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["db_path"].endswith("fleet.db")
    assert payload["tables"]["devices"] == 0
    assert "idx_compliance_runs_started_at" in payload["indexes"]
