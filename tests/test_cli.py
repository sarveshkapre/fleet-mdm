import json
from pathlib import Path

from typer.testing import CliRunner

from fleetmdm.cli import app

runner = CliRunner()


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

    assert metadata["redaction_profile"] == "strict"
    assert all(entry["device_id"].startswith("device-") for entry in inventory)
    assert all(entry["serial"].startswith("serial-") for entry in inventory)
    assert latest_run["results"][0]["device_id"].startswith("device-")


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
