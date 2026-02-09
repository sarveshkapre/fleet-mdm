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
    ]:
        assert (output_dir / filename).exists()

    metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))
    latest_run = json.loads((output_dir / "latest_run.json").read_text(encoding="utf-8"))
    assert metadata["schema_version"] == 1
    assert latest_run["run_id"].startswith("run-")
