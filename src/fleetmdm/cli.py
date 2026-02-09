from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent
from typing import Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from fleetmdm import __version__
from fleetmdm.crypto import sha256_text
from fleetmdm.inventory import inventory_json_schema, load_inventory_json
from fleetmdm.policy import (
    evaluate_policy,
    load_policy,
    load_policy_from_file,
    policy_matches_targets,
    validate_policy_file,
)
from fleetmdm.report import render_csv, render_json, render_table
from fleetmdm.store import (
    add_compliance_result,
    add_policy,
    add_script,
    assign_policy,
    assign_policy_to_tag,
    connect,
    create_compliance_run,
    device_exists,
    export_inventory,
    get_device,
    get_device_facts,
    get_policy_yaml,
    get_tag_assigned_policies,
    has_any_policy_assignments,
    ingest_devices,
    init_db,
    list_all_policy_assignments,
    list_all_policy_tag_assignments,
    list_compliance_history,
    list_devices,
    list_policies,
    list_policy_assignments_for_device,
    list_policy_assignments_for_tag,
    list_recent_runs,
    list_results_for_run,
    list_scripts,
    policy_exists,
    resolve_assigned_policies_for_device,
    resolve_db_path,
    unassign_policy,
    unassign_policy_from_tag,
)

ARG_DEVICE_JSON = typer.Argument(..., exists=True, readable=True, help="Device JSON file")
ARG_INVENTORY_JSON = typer.Argument(..., exists=True, readable=True, help="Inventory JSON file")
ARG_POLICY_FILE = typer.Argument(..., exists=True, readable=True)
ARG_SCRIPT_FILE = typer.Argument(..., exists=True, readable=True)
OPT_DB = typer.Option(None, "--db", help="Path to SQLite DB")
OPT_OUTPUT = typer.Option(None, "--output", help="Write JSON to file")
OPT_DEVICE = typer.Option(..., "--device", help="Device ID")
OPT_DEVICE_OPTIONAL = typer.Option(None, "--device", help="Device ID")
OPT_NAME = typer.Option(None, "--name", help="Script name")
OPT_POLICY_ID_OPTIONAL = typer.Option(None, "--policy", help="Policy ID")
OPT_LIMIT = typer.Option(50, "--limit", help="Limit rows")
OPT_EVIDENCE_OUTPUT = typer.Option(None, "--output", help="Directory for evidence bundle")

app = typer.Typer(help="FleetMDM CLI", add_completion=False)
inventory_app = typer.Typer(help="Inventory tools")
policy_app = typer.Typer(help="Policy management")
script_app = typer.Typer(help="Script catalog")
schema_app = typer.Typer(help="Schema export")
evidence_app = typer.Typer(help="Evidence export")
app.add_typer(inventory_app, name="inventory")
app.add_typer(policy_app, name="policy")
app.add_typer(script_app, name="script")
app.add_typer(schema_app, name="schema")
app.add_typer(evidence_app, name="evidence")

console = Console()


def _normalize_tag(tag: str) -> str:
    return tag.strip().lower()


def _extract_device_tags(facts: dict[str, Any]) -> list[str]:
    raw = facts.get("tags")
    if raw is None:
        return []
    if isinstance(raw, str):
        items: list[Any] = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        return []

    tags: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            continue
        normalized = _normalize_tag(item)
        if not normalized or normalized in seen:
            continue
        tags.append(normalized)
        seen.add(normalized)
    return tags


def _build_evaluation_context(
    device: Mapping[str, Any], facts: dict[str, Any]
) -> dict[str, Any]:
    context = dict(facts)
    for key in ("device_id", "hostname", "os", "os_version", "serial", "last_seen"):
        value = device.get(key)
        if value is not None:
            context[key] = value
    return context


def _policy_name_map(conn: sqlite3.Connection) -> dict[str, str]:
    return {str(row["policy_id"]): str(row["name"]) for row in list_policies(conn)}


def _load_devices_from_json(path: Path) -> list[dict[str, Any]]:
    return load_inventory_json(path)


def _compute_drift_changes(
    latest: Sequence[Any], previous: Sequence[Any]
) -> list[dict[str, str]]:
    latest_map = {
        (str(row["device_id"]), str(row["policy_id"])): str(row["status"]) for row in latest
    }
    previous_map = {
        (str(row["device_id"]), str(row["policy_id"])): str(row["status"]) for row in previous
    }

    changes: list[dict[str, str]] = []
    for key, current in latest_map.items():
        previous_status = previous_map.get(key)
        if previous_status is None or previous_status == current:
            continue
        device_id, policy_id = key
        changes.append(
            {
                "device_id": device_id,
                "policy_id": policy_id,
                "previous": previous_status,
                "current": current,
            }
        )
    return changes


@inventory_app.command("validate")
def inventory_validate(
    path: Path = ARG_INVENTORY_JSON,
) -> None:
    """Validate inventory JSON against the schema."""
    try:
        load_inventory_json(path)
    except (ValueError, ValidationError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print("OK")


@schema_app.command("inventory")
def schema_inventory(
    output: Path | None = OPT_OUTPUT,
) -> None:
    """Print the inventory JSON schema (for agent/exporter authors)."""
    text = json.dumps(inventory_json_schema(), indent=2)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        console.print(text)


@app.command()
def version() -> None:
    console.print(__version__)


@app.command()
def init(db: str | None = typer.Option(None, "--db", help="Path to SQLite DB")) -> None:
    """Initialize the FleetMDM database."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    console.print(f"Initialized DB at {db_path}")


@app.command()
def ingest(
    path: Path = ARG_DEVICE_JSON,
    db: str | None = OPT_DB,
) -> None:
    """Ingest device inventory JSON."""
    try:
        devices = _load_devices_from_json(path)
    except (ValueError, ValidationError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        for device in devices:
            if not device.get("last_seen"):
                device["last_seen"] = conn.execute("SELECT datetime('now')").fetchone()[0]
        count = ingest_devices(conn, devices)
    console.print(f"Ingested {count} device(s)")


@app.command()
def export(
    output: Path | None = OPT_OUTPUT,
    db: str | None = OPT_DB,
) -> None:
    """Export inventory as JSON."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        payload = export_inventory(conn)
    text = json.dumps(payload, indent=2)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        console.print(text)


@policy_app.command("validate")
def policy_validate(path: Path = ARG_POLICY_FILE) -> None:
    """Validate a policy file."""
    errors = validate_policy_file(str(path))
    if errors:
        for error in errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1)
    console.print("OK")


@policy_app.command("add")
def policy_add(
    path: Path = ARG_POLICY_FILE,
    db: str | None = OPT_DB,
) -> None:
    """Add or update a policy."""
    try:
        policy, raw_yaml = load_policy_from_file(str(path))
    except (ValueError, ValidationError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        add_policy(conn, policy.id, policy.name, policy.description, raw_yaml)
    console.print(f"Saved policy {policy.id}")


@policy_app.command("list")
def policy_list(
    db: str | None = OPT_DB,
) -> None:
    """List policies."""
    db_path = resolve_db_path(db)
    with connect(db_path) as conn:
        rows = list_policies(conn)
    table = Table(title="Policies")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Updated")
    for row in rows:
        table.add_row(row["policy_id"], row["name"], row["updated_at"])
    console.print(table)


@policy_app.command("assign")
def policy_assign(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    tag: str | None = typer.Option(None, "--tag", help="Assign to devices with a tag"),
    db: str | None = OPT_DB,
) -> None:
    """Assign a policy to a device or tag."""
    if (device_id is None) == (tag is None):
        console.print("Provide exactly one of --device or --tag")
        raise typer.Exit(code=2)

    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        if not policy_exists(conn, policy_id):
            console.print(f"[red]Unknown policy: {policy_id}[/red]")
            raise typer.Exit(code=1)

        if tag is not None:
            normalized_tag = _normalize_tag(tag)
            if not normalized_tag:
                console.print("[red]--tag cannot be empty[/red]")
                raise typer.Exit(code=2)
            assign_policy_to_tag(conn, policy_id, normalized_tag)

            matches = 0
            for row in list_devices(conn):
                facts = get_device_facts(conn, str(row["device_id"])) or {}
                if normalized_tag in _extract_device_tags(facts):
                    matches += 1
            console.print(
                f"Assigned {policy_id} to tag '{normalized_tag}' ({matches} device(s) match)"
            )
            return

        if device_id is None:
            console.print("Provide exactly one of --device or --tag")
            raise typer.Exit(code=2)
        if not device_exists(conn, device_id):
            console.print(f"[red]Unknown device: {device_id}[/red]")
            raise typer.Exit(code=1)
        assign_policy(conn, policy_id, device_id)
    console.print(f"Assigned {policy_id} to {device_id}")


@policy_app.command("unassign")
def policy_unassign(
    policy_id: str = typer.Argument(..., help="Policy ID"),
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    tag: str | None = typer.Option(None, "--tag", help="Remove tag assignment"),
    db: str | None = OPT_DB,
) -> None:
    """Remove a policy assignment from a device or tag."""
    if (device_id is None) == (tag is None):
        console.print("Provide exactly one of --device or --tag")
        raise typer.Exit(code=2)

    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        if not policy_exists(conn, policy_id):
            console.print(f"[red]Unknown policy: {policy_id}[/red]")
            raise typer.Exit(code=1)

        if tag is not None:
            normalized_tag = _normalize_tag(tag)
            if not normalized_tag:
                console.print("[red]--tag cannot be empty[/red]")
                raise typer.Exit(code=2)
            removed = unassign_policy_from_tag(conn, policy_id, normalized_tag)
            if removed:
                console.print(f"Unassigned {policy_id} from tag '{normalized_tag}'")
            else:
                console.print(f"No assignment found for {policy_id} on tag '{normalized_tag}'")
            return

        if device_id is None:
            console.print("Provide exactly one of --device or --tag")
            raise typer.Exit(code=2)
        if not device_exists(conn, device_id):
            console.print(f"[red]Unknown device: {device_id}[/red]")
            raise typer.Exit(code=1)
        removed = unassign_policy(conn, policy_id, device_id)
        if removed:
            console.print(f"Unassigned {policy_id} from {device_id}")
        else:
            console.print(f"No assignment found for {policy_id} on {device_id}")


@policy_app.command("assignments")
def policy_assignments(
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    tag: str | None = typer.Option(None, "--tag", help="Show assignments for a tag"),
    db: str | None = OPT_DB,
) -> None:
    """Show policy assignments for a device or tag."""
    if (device_id is None) == (tag is None):
        console.print("Provide exactly one of --device or --tag")
        raise typer.Exit(code=2)

    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        name_map = _policy_name_map(conn)
        if tag is not None:
            normalized_tag = _normalize_tag(tag)
            if not normalized_tag:
                console.print("[red]--tag cannot be empty[/red]")
                raise typer.Exit(code=2)

            policy_ids = list_policy_assignments_for_tag(conn, normalized_tag)
            table = Table(title=f"Policy Assignments for tag '{normalized_tag}'")
            table.add_column("Policy ID")
            table.add_column("Name")
            if policy_ids:
                for pid in policy_ids:
                    table.add_row(pid, name_map.get(pid, ""))
            else:
                table.add_row("(none)", "")
            console.print(table)
            return

        if device_id is None:
            console.print("Provide exactly one of --device or --tag")
            raise typer.Exit(code=2)
        if not device_exists(conn, device_id):
            console.print(f"[red]Unknown device: {device_id}[/red]")
            raise typer.Exit(code=1)

        facts = get_device_facts(conn, device_id) or {}
        tags = _extract_device_tags(facts)
        direct = list_policy_assignments_for_device(conn, device_id)
        by_tag = get_tag_assigned_policies(conn, tags)
        effective = resolve_assigned_policies_for_device(conn, device_id, tags)

        console.print(f"Device: {device_id}")
        console.print(f"Tags: {', '.join(tags) if tags else '(none)'}")

        direct_table = Table(title="Direct Assignments")
        direct_table.add_column("Policy ID")
        direct_table.add_column("Name")
        if direct:
            for pid in direct:
                direct_table.add_row(pid, name_map.get(pid, ""))
        else:
            direct_table.add_row("(none)", "")
        console.print(direct_table)

        tag_table = Table(title="Tag Assignments (matched)")
        tag_table.add_column("Policy ID")
        tag_table.add_column("Name")
        if by_tag:
            for pid in by_tag:
                tag_table.add_row(pid, name_map.get(pid, ""))
        else:
            tag_table.add_row("(none)", "")
        console.print(tag_table)

        effective_table = Table(title="Effective Policies")
        effective_table.add_column("Policy ID")
        effective_table.add_column("Name")
        if effective:
            for pid in effective:
                effective_table.add_row(pid, name_map.get(pid, ""))
        else:
            effective_table.add_row("(none)", "")
        console.print(effective_table)


@app.command()
def check(
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Evaluate compliance."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        assignment_mode = has_any_policy_assignments(conn)
        policy_rows = list_policies(conn)
        all_policy_ids = [str(row["policy_id"]) for row in policy_rows]
        run_id = create_compliance_run(conn)
        devices = [row["device_id"] for row in list_devices(conn)]
        if device_id:
            if not device_exists(conn, device_id):
                console.print(f"[red]Unknown device: {device_id}[/red]")
                raise typer.Exit(code=1)
            devices = [device_id]

        if not devices:
            console.print("No devices found")
            raise typer.Exit(code=1)

        results_payload = []
        for did in devices:
            facts = get_device_facts(conn, did)
            if facts is None:
                continue
            device = get_device(conn, did)
            if device is None:
                continue
            device_data = dict(device)
            evaluation_context = _build_evaluation_context(device_data, facts)

            tags = _extract_device_tags(facts)
            policy_ids = (
                resolve_assigned_policies_for_device(conn, did, tags)
                if assignment_mode
                else all_policy_ids
            )
            if assignment_mode and not policy_ids:
                if device_id:
                    console.print(
                        f"No policies assigned to {did} "
                        "(device assignments or matching tag assignments)"
                    )
                    raise typer.Exit(code=1)
                continue

            policy_results = []
            for pid in policy_ids:
                raw_yaml = get_policy_yaml(conn, pid)
                if not raw_yaml:
                    continue
                policy = load_policy(raw_yaml)
                if not policy_matches_targets(policy, device_data, facts):
                    continue
                result = evaluate_policy(policy, evaluation_context)
                policy_results.append(result)
                failed = [c.key for c in result.checks if not c.passed]
                add_compliance_result(
                    conn,
                    run_id,
                    did,
                    result.policy_id,
                    result.policy_name,
                    "pass" if result.passed else "fail",
                    ", ".join(failed),
                )

            if not policy_results:
                if device_id:
                    console.print("No policies to evaluate")
                    raise typer.Exit(code=1)
                continue

            results_payload.append({"device_id": did, "results": policy_results})

    if not results_payload:
        console.print("No policies to evaluate")
        raise typer.Exit(code=1)

    if format == "table":
        if len(results_payload) > 1:
            console.print("Table format requires --device")
            raise typer.Exit(code=1)
        console.print(render_table(results_payload[0]["results"]))
        return
    if format == "json":
        payload = []
        for entry in results_payload:
            payload.append(
                {
                    "device_id": entry["device_id"],
                    "results": json.loads(render_json(entry["results"])),
                }
            )
        console.print(json.dumps(payload, indent=2))
        return
    if format == "csv":
        lines = ["device_id,policy_id,policy_name,status,failed_checks"]
        for entry in results_payload:
            csv_text = render_csv(entry["results"]).splitlines()[1:]
            for row in csv_text:
                lines.append(f"{entry['device_id']},{row}")
        console.print("\n".join(lines))
        return
    console.print(f"Unknown format: {format}")
    raise typer.Exit(code=1)


@app.command()
def report(
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Summary compliance report across devices."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        assignment_mode = has_any_policy_assignments(conn)
        policy_rows = list_policies(conn)
        device_rows = list_devices(conn)
        if not policy_rows or not device_rows:
            console.print("No data to report")
            raise typer.Exit(code=1)

        summary: dict[str, dict[str, Any]] = {}
        for policy in policy_rows:
            summary[policy["policy_id"]] = {
                "policy_id": policy["policy_id"],
                "policy_name": policy["name"],
                "passed_count": 0,
                "failed_count": 0,
            }

        for device in device_rows:
            facts = get_device_facts(conn, device["device_id"]) or {}
            device_data = dict(device)
            evaluation_context = _build_evaluation_context(device_data, facts)
            tags = _extract_device_tags(facts)
            applicable = (
                resolve_assigned_policies_for_device(conn, device["device_id"], tags)
                if assignment_mode
                else [row["policy_id"] for row in policy_rows]
            )
            if assignment_mode and not applicable:
                continue
            for pid in applicable:
                raw_yaml = get_policy_yaml(conn, pid)
                if not raw_yaml:
                    continue
                policy = load_policy(raw_yaml)
                if not policy_matches_targets(policy, device_data, facts):
                    continue
                result = evaluate_policy(policy, evaluation_context)
                if result.passed:
                    summary[pid]["passed_count"] += 1
                else:
                    summary[pid]["failed_count"] += 1

    if format == "json":
        console.print(json.dumps(list(summary.values()), indent=2))
        return
    if format == "csv":
        rows = ["policy_id,policy_name,passed,failed"]
        for row in summary.values():
            rows.append(
                f"{row['policy_id']},{row['policy_name']},{row['passed_count']},{row['failed_count']}"
            )
        console.print("\n".join(rows))
        return

    table = Table(title="Compliance Summary")
    table.add_column("Policy")
    table.add_column("Pass")
    table.add_column("Fail")
    for row in summary.values():
        table.add_row(row["policy_name"], str(row["passed_count"]), str(row["failed_count"]))
    console.print(table)


@app.command()
def history(
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    policy_id: str | None = OPT_POLICY_ID_OPTIONAL,
    limit: int = OPT_LIMIT,
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Show compliance history."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        rows = list_compliance_history(conn, device_id, policy_id, limit)

    if format == "json":
        console.print(json.dumps([dict(row) for row in rows], indent=2))
        return
    if format == "csv":
        lines = ["run_id,device_id,policy_id,policy_name,status,failed_checks,checked_at"]
        for row in rows:
            lines.append(
                f"{row['run_id']},{row['device_id']},{row['policy_id']},"
                f"{row['policy_name']},{row['status']},{row['failed_checks']},"
                f"{row['checked_at']}"
            )
        console.print("\n".join(lines))
        return

    table = Table(title="Compliance History")
    table.add_column("Run")
    table.add_column("Device")
    table.add_column("Policy")
    table.add_column("Status")
    table.add_column("Failed Checks")
    table.add_column("Checked At")
    for row in rows:
        table.add_row(
            row["run_id"],
            row["device_id"],
            row["policy_name"],
            row["status"],
            row["failed_checks"],
            row["checked_at"],
        )
    console.print(table)


@app.command()
def drift(
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Compare the last two compliance runs and show status changes."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        runs = list_recent_runs(conn, 2)
        if len(runs) < 2:
            console.print("Need at least two compliance runs to calculate drift")
            raise typer.Exit(code=1)
        latest_run = runs[0]["run_id"]
        previous_run = runs[1]["run_id"]
        latest = list_results_for_run(conn, latest_run)
        previous = list_results_for_run(conn, previous_run)
    changes = _compute_drift_changes(latest, previous)

    if format == "json":
        console.print(json.dumps(changes, indent=2))
        return
    if format == "csv":
        lines = ["device_id,policy_id,previous,current"]
        for row in changes:
            lines.append(
                f"{row['device_id']},{row['policy_id']},{row['previous']},{row['current']}"
            )
        console.print("\n".join(lines))
        return

    table = Table(title="Compliance Drift (last two runs)")
    table.add_column("Device")
    table.add_column("Policy")
    table.add_column("Previous")
    table.add_column("Current")
    if not changes:
        table.add_row("(none)", "", "", "")
    else:
        for row in changes:
            table.add_row(row["device_id"], row["policy_id"], row["previous"], row["current"])
    console.print(table)


@evidence_app.command("export")
def evidence_export(
    output: Path | None = OPT_EVIDENCE_OUTPUT,
    db: str | None = OPT_DB,
) -> None:
    """Export a SOC-style evidence bundle as JSON artifacts."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = output or Path(f"fleetmdm-evidence-{stamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        inventory = export_inventory(conn)
        policies: list[dict[str, Any]] = []
        for row in list_policies(conn):
            policy_id = str(row["policy_id"])
            policies.append(
                {
                    "policy_id": policy_id,
                    "name": str(row["name"]),
                    "description": row["description"],
                    "updated_at": str(row["updated_at"]),
                    "raw_yaml": get_policy_yaml(conn, policy_id),
                }
            )

        device_assignments = [
            {"policy_id": str(row["policy_id"]), "device_id": str(row["device_id"])}
            for row in list_all_policy_assignments(conn)
        ]
        tag_assignments = [
            {"policy_id": str(row["policy_id"]), "tag": str(row["tag"])}
            for row in list_all_policy_tag_assignments(conn)
        ]

        runs = list_recent_runs(conn, 2)
        latest_run: dict[str, Any] = {}
        drift_changes: list[dict[str, str]] = []
        if runs:
            latest_run_id = str(runs[0]["run_id"])
            latest_results = [dict(row) for row in list_results_for_run(conn, latest_run_id)]
            latest_run = {
                "run_id": latest_run_id,
                "started_at": str(runs[0]["started_at"]),
                "results": latest_results,
            }
            if len(runs) > 1:
                previous_run_id = str(runs[1]["run_id"])
                previous_results = list_results_for_run(conn, previous_run_id)
                drift_changes = _compute_drift_changes(latest_results, previous_results)

    metadata = {
        "generated_at": generated_at,
        "db_path": str(db_path),
        "schema_version": 1,
        "artifact_count": 6,
    }
    assignments = {"device": device_assignments, "tag": tag_assignments}

    artifacts = {
        "metadata.json": metadata,
        "inventory.json": inventory,
        "policies.json": policies,
        "assignments.json": assignments,
        "latest_run.json": latest_run,
        "drift.json": drift_changes,
    }
    for name, payload in artifacts.items():
        (output_dir / name).write_text(f"{json.dumps(payload, indent=2)}\n", encoding="utf-8")

    console.print(f"Wrote evidence pack to {output_dir}")


@script_app.command("add")
def script_add(
    path: Path = ARG_SCRIPT_FILE,
    name: str = OPT_NAME,
    db: str | None = OPT_DB,
) -> None:
    """Add a script to the catalog (metadata only)."""
    content = path.read_text(encoding="utf-8")
    script_name = name or path.name
    script_id = f"script-{sha256_text(script_name)[:8]}"
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        add_script(conn, script_id, script_name, sha256_text(content), content)
    console.print(f"Saved {script_name} as {script_id}")


@script_app.command("list")
def script_list(
    db: str | None = OPT_DB,
) -> None:
    """List scripts in the catalog."""
    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        rows = list_scripts(conn)
    table = Table(title="Scripts")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("SHA256")
    for row in rows:
        table.add_row(row["script_id"], row["name"], row["sha256"])
    console.print(table)


@app.command()
def seed(
    db: str | None = OPT_DB,
) -> None:
    """Seed sample devices and policies."""
    sample_devices = [
        {
            "device_id": "mac-001",
            "hostname": "studio-1",
            "os": "macos",
            "os_version": "14.4",
            "serial": "C02XYZ123",
            "facts": {"disk": {"encrypted": True}, "cpu": {"cores": 8}},
            "last_seen": "",
        },
        {
            "device_id": "linux-001",
            "hostname": "render-1",
            "os": "linux",
            "os_version": "22.04",
            "serial": "LINUX123",
            "facts": {"disk": {"encrypted": False}, "cpu": {"cores": 16}},
            "last_seen": "",
        },
    ]

    policy_yaml = dedent(
        """
        id: min-os-version
        name: Minimum OS Version
        description: Require OS version >= 14.0 for macOS and >= 22.04 for Linux
        checks:
          - key: os_version
            op: version_gte
            value: "14.0"
        """
    ).strip()

    db_path = resolve_db_path(db)
    init_db(db_path)
    with connect(db_path) as conn:
        for device in sample_devices:
            if not device.get("last_seen"):
                device["last_seen"] = conn.execute("SELECT datetime('now')").fetchone()[0]
        ingest_devices(conn, sample_devices)
        policy = load_policy(policy_yaml)
        add_policy(conn, policy.id, policy.name, policy.description, policy_yaml)
    console.print("Seeded sample data")
