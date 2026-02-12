from __future__ import annotations

import base64
import contextlib
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from textwrap import dedent
from typing import Any

import typer
import yaml
from click.core import ParameterSource
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from fleetmdm import __version__
from fleetmdm.crypto import sha256_text
from fleetmdm.csvutil import csv_safe_cell
from fleetmdm.inventory import inventory_json_schema, load_inventory_json
from fleetmdm.policy import (
    Policy,
    evaluate_policy,
    load_policy,
    load_policy_from_file,
    policy_matches_targets,
    validate_policy_file,
)
from fleetmdm.report import (
    render_json,
    render_junit_summary,
    render_sarif_summary,
    render_table,
)
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
    get_policy,
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
    utc_now,
)

ARG_DEVICE_JSON = typer.Argument(..., exists=True, readable=True, help="Device JSON file")
ARG_INVENTORY_JSON = typer.Argument(..., exists=True, readable=True, help="Inventory JSON file")
ARG_POLICY_FILE = typer.Argument(..., exists=True, readable=True)
ARG_POLICY_PATH = typer.Argument(
    ...,
    exists=True,
    readable=True,
    help="Policy YAML file or directory",
)
ARG_SCRIPT_FILE = typer.Argument(..., exists=True, readable=True)
OPT_DB = typer.Option(None, "--db", help="Path to SQLite DB")
OPT_OUTPUT = typer.Option(None, "--output", help="Write JSON to file")
OPT_DEVICE = typer.Option(..., "--device", help="Device ID")
OPT_DEVICE_OPTIONAL = typer.Option(None, "--device", help="Device ID")
OPT_NAME = typer.Option(None, "--name", help="Script name")
OPT_POLICY_ID_OPTIONAL = typer.Option(None, "--policy", help="Policy ID")
OPT_SINCE = typer.Option(None, "--since", help="ISO8601 timestamp (filters newer-than-or-equal)")
OPT_LIMIT = typer.Option(50, "--limit", help="Limit rows")
OPT_EVIDENCE_OUTPUT = typer.Option(None, "--output", help="Directory for evidence bundle")
OPT_REDACT_PROFILE = typer.Option(
    "none",
    "--redact-profile",
    help="Evidence redaction profile: none|minimal|strict",
)
OPT_SIGNING_KEY_FILE = typer.Option(
    None,
    "--signing-key-file",
    exists=True,
    readable=True,
    help="Path to key file used to HMAC-sign evidence manifests",
)
OPT_KEYRING_DIR = typer.Option(
    None,
    "--keyring-dir",
    exists=True,
    file_okay=False,
    dir_okay=True,
    readable=True,
    help="Directory of signing keys; selects key by signature.json key_id",
)
OPT_KEYRING_DIR_CREATE = typer.Option(
    None,
    "--keyring-dir",
    file_okay=False,
    dir_okay=True,
    help="Directory of signing keys (will be created if missing)",
)
OPT_REDACT_CONFIG = typer.Option(
    None,
    "--redact-config",
    exists=True,
    readable=True,
    help="YAML/JSON file with additional redactions for evidence inventory facts",
)
OPT_HISTORY_LIMIT = typer.Option(
    0,
    "--history-limit",
    min=0,
    help="Include up to N most recent compliance history rows in evidence export (0 disables)",
)
OPT_EVIDENCE_KEY_OUTPUT = typer.Option(None, "--output", help="Path to write signing key")
OPT_FORCE = typer.Option(False, "--force", help="Overwrite output file if it exists")
OPT_VERIFY_FORMAT = typer.Option("text", "--format", help="text/json")
OPT_VERIFY_OUTPUT = typer.Option(
    None,
    "--output",
    help="Write verification report to a file (JSON only; suppresses stdout report)",
)
ARG_EVIDENCE_DIR = typer.Argument(
    ...,
    exists=True,
    file_okay=False,
    dir_okay=True,
    readable=True,
    help="Evidence bundle directory",
)

ALLOWED_REDACTION_PROFILES = {"none", "minimal", "strict"}
DEFAULT_CONFIG_PATH = "~/.fleetmdm/config.yaml"

app = typer.Typer(help="FleetMDM CLI", add_completion=False)
inventory_app = typer.Typer(help="Inventory tools")
policy_app = typer.Typer(help="Policy management")
script_app = typer.Typer(help="Script catalog")
schema_app = typer.Typer(help="Schema export")
evidence_app = typer.Typer(help="Evidence export")
evidence_key_app = typer.Typer(help="Signing key management")
app.add_typer(inventory_app, name="inventory")
app.add_typer(policy_app, name="policy")
app.add_typer(script_app, name="script")
app.add_typer(schema_app, name="schema")
app.add_typer(evidence_app, name="evidence")
evidence_app.add_typer(evidence_key_app, name="key")

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


def _device_tags_by_id(conn: sqlite3.Connection) -> dict[str, list[str]]:
    tags_by_device: dict[str, list[str]] = {}
    for row in list_devices(conn):
        device_id = str(row["device_id"])
        facts = get_device_facts(conn, device_id) or {}
        tags_by_device[device_id] = _extract_device_tags(facts)
    return tags_by_device


def _load_devices_from_json(path: Path) -> list[dict[str, Any]]:
    return load_inventory_json(path)


def _iter_policy_lint_paths(path: Path, *, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]

    pattern_method = path.rglob if recursive else path.glob
    files = sorted(
        [candidate for candidate in pattern_method("*.y*ml") if candidate.is_file()],
        key=lambda item: str(item),
    )
    return files


def _lint_policy_semantics(policy: Policy) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    targets = policy.targets or {}
    os_target = targets.get("os")
    if os_target is not None and not isinstance(os_target, (str, list)):
        errors.append("targets.os must be a string or list of strings")
    if isinstance(os_target, list):
        invalid_os_items = [item for item in os_target if not isinstance(item, str)]
        if invalid_os_items:
            errors.append("targets.os list must contain only strings")

    tags_target = targets.get("tags")
    if tags_target is not None and not isinstance(tags_target, (str, list)):
        errors.append("targets.tags must be a string or list of strings")
    if isinstance(tags_target, list):
        normalized_tags = [str(item).strip().lower() for item in tags_target if str(item).strip()]
        if len(set(normalized_tags)) < len(normalized_tags):
            warnings.append("targets.tags contains duplicate values after normalization")
        invalid_tag_items = [item for item in tags_target if not isinstance(item, str)]
        if invalid_tag_items:
            errors.append("targets.tags list must contain only strings")

    seen_checks: set[tuple[str, str, str]] = set()
    for index, check in enumerate(policy.checks, start=1):
        signature = (check.key.strip(), check.op.strip(), json.dumps(check.value, sort_keys=True))
        if signature in seen_checks:
            warnings.append(
                f"checks[{index}] duplicates an earlier check "
                f"({check.key} {check.op} {check.value!r})"
            )
        seen_checks.add(signature)

        if check.op in {"in", "not_in"} and (
            not isinstance(check.value, list) or len(check.value) == 0
        ):
            errors.append(
                f"checks[{index}] uses '{check.op}' but value must be a non-empty list"
            )
        if check.op == "regex":
            try:
                re.compile(str(check.value))
            except re.error as exc:
                errors.append(f"checks[{index}] invalid regex pattern: {exc}")

    return errors, warnings


def _lint_policy_file(path: Path) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "path": str(path),
        "policy_id": None,
        "ok": False,
        "errors": [],
        "warnings": [],
    }

    schema_errors = validate_policy_file(str(path))
    if schema_errors:
        payload["errors"] = list(schema_errors)
        return payload

    try:
        policy, _raw_yaml = load_policy_from_file(str(path))
    except (ValueError, ValidationError) as exc:
        payload["errors"] = [str(exc)]
        return payload

    semantic_errors, warnings = _lint_policy_semantics(policy)
    payload["policy_id"] = policy.id
    payload["errors"] = semantic_errors
    payload["warnings"] = warnings
    payload["ok"] = len(semantic_errors) == 0
    return payload


def _compute_drift_changes(
    latest: Sequence[Any], previous: Sequence[Any], *, include_new_missing: bool = False
) -> list[dict[str, str]]:
    def to_result_map(rows: Sequence[Any]) -> dict[tuple[str, str], dict[str, str]]:
        result: dict[tuple[str, str], dict[str, str]] = {}
        for row in rows:
            device_id = str(row["device_id"])
            policy_id = str(row["policy_id"])
            policy_name_value: Any = None
            try:
                policy_name_value = row["policy_name"]
            except Exception:
                policy_name_value = None
            policy_name = "" if policy_name_value is None else str(policy_name_value)
            result[(device_id, policy_id)] = {
                "status": str(row["status"]),
                "policy_name": policy_name,
            }
        return result

    latest_map = to_result_map(latest)
    previous_map = to_result_map(previous)

    changes: list[dict[str, str]] = []
    shared_keys = sorted(set(latest_map.keys()) & set(previous_map.keys()))
    for key in shared_keys:
        current = latest_map[key]
        previous_row = previous_map[key]
        if previous_row["status"] == current["status"]:
            continue
        device_id, policy_id = key
        changes.append(
            {
                "device_id": device_id,
                "policy_id": policy_id,
                "policy_name": current.get("policy_name", ""),
                "previous": previous_row["status"],
                "current": current["status"],
                "change_type": "changed",
            }
        )

    if not include_new_missing:
        return changes

    latest_only = sorted(set(latest_map.keys()) - set(previous_map.keys()))
    for device_id, policy_id in latest_only:
        current = latest_map[(device_id, policy_id)]
        changes.append(
            {
                "device_id": device_id,
                "policy_id": policy_id,
                "policy_name": current.get("policy_name", ""),
                "previous": "missing",
                "current": current["status"],
                "change_type": "new",
            }
        )

    previous_only = sorted(set(previous_map.keys()) - set(latest_map.keys()))
    for device_id, policy_id in previous_only:
        previous_row = previous_map[(device_id, policy_id)]
        changes.append(
            {
                "device_id": device_id,
                "policy_id": policy_id,
                "policy_name": previous_row.get("policy_name", ""),
                "previous": previous_row["status"],
                "current": "missing",
                "change_type": "missing",
            }
        )

    return changes


def _json_payload_text(payload: Any) -> str:
    return f"{json.dumps(payload, indent=2, sort_keys=True)}\n"


def _write_json_artifact(path: Path, payload: Any) -> None:
    path.write_text(_json_payload_text(payload), encoding="utf-8")


def _hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _key_id_for_bytes(key_bytes: bytes) -> str:
    return _hash_bytes(key_bytes)[:16]


def _normalize_redaction_profile(profile: str) -> str:
    normalized = profile.strip().lower()
    if normalized not in ALLOWED_REDACTION_PROFILES:
        raise ValueError(
            f"Invalid redaction profile: {profile}. "
            "Expected one of none|minimal|strict."
        )
    return normalized


def _redact_serial(serial: str, profile: str) -> str:
    if profile == "none":
        return serial
    if profile == "minimal":
        suffix = serial[-4:] if len(serial) > 4 else serial
        return f"***{suffix}"
    return f"serial-{sha256_text(serial)[:12]}"


def _redact_device_id(device_id: str, profile: str) -> str:
    if profile != "strict":
        return device_id
    return f"device-{sha256_text(device_id)[:12]}"


def _apply_redaction_profile(
    profile: str,
    inventory: Sequence[dict[str, Any]],
    device_assignments: Sequence[dict[str, str]],
    latest_run: dict[str, Any],
    drift_changes: Sequence[dict[str, str]],
    history_rows: Sequence[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, str]],
    dict[str, Any],
    list[dict[str, str]],
    list[dict[str, Any]],
]:
    device_map: dict[str, str] = {}

    def redact_device_id(value: str) -> str:
        if value not in device_map:
            device_map[value] = _redact_device_id(value, profile)
        return device_map[value]

    redacted_inventory: list[dict[str, Any]] = []
    for record in inventory:
        row = dict(record)
        device_id = str(row["device_id"])
        row["device_id"] = redact_device_id(device_id)
        row["serial"] = _redact_serial(str(row["serial"]), profile)
        redacted_inventory.append(row)

    redacted_assignments: list[dict[str, str]] = []
    for assignment in device_assignments:
        row = dict(assignment)
        row["device_id"] = redact_device_id(str(row["device_id"]))
        redacted_assignments.append(row)

    redacted_latest_run = dict(latest_run)
    if redacted_latest_run:
        results = []
        for result in redacted_latest_run.get("results", []):
            row = dict(result)
            row["device_id"] = redact_device_id(str(row["device_id"]))
            results.append(row)
        redacted_latest_run["results"] = results

    redacted_drift: list[dict[str, str]] = []
    for change in drift_changes:
        row = dict(change)
        row["device_id"] = redact_device_id(str(row["device_id"]))
        redacted_drift.append(row)

    redacted_history: list[dict[str, Any]] = []
    for entry in history_rows:
        row = dict(entry)
        device_id = str(row.get("device_id", "")).strip()
        if device_id:
            row["device_id"] = redact_device_id(device_id)
        redacted_history.append(row)

    return (
        redacted_inventory,
        redacted_assignments,
        redacted_latest_run,
        redacted_drift,
        redacted_history,
    )


def _build_manifest(
    output_dir: Path, artifact_names: Sequence[str], generated_at: str, redaction_profile: str
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for name in sorted(artifact_names):
        content = (output_dir / name).read_bytes()
        entries.append(
            {
                "name": name,
                "sha256": _hash_bytes(content),
                "size_bytes": len(content),
            }
        )
    bundle_material = "\n".join(f"{entry['name']}:{entry['sha256']}" for entry in entries)
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "redaction_profile": redaction_profile,
        "artifact_count": len(entries),
        "bundle_sha256": sha256_text(bundle_material),
        "artifacts": entries,
    }


def _sign_manifest(manifest_bytes: bytes, key_bytes: bytes, generated_at: str) -> dict[str, Any]:
    signature = hmac.new(key_bytes, manifest_bytes, hashlib.sha256).hexdigest()
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "signed_at": generated_at,
        "algorithm": "hmac-sha256",
        "key_id": _key_id_for_bytes(key_bytes),
        "manifest_sha256": _hash_bytes(manifest_bytes),
        "signature": signature,
    }


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    # Accept both "...Z" and "...+00:00" forms.
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _json_error_payload(
    code: str, message: str, details: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if details:
        payload["error"]["details"] = dict(details)
    return payload


def _exit_with_error(
    *,
    message: str,
    error_code: str,
    exit_code: int = 1,
    json_output: bool = False,
    details: Mapping[str, Any] | None = None,
) -> None:
    if json_output:
        typer.echo(_json_payload_text(_json_error_payload(error_code, message, details)), nl=False)
    else:
        console.print(message)
    raise typer.Exit(code=exit_code)


def _normalize_since_option(value: str | None, *, json_output: bool = False) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    dt = _parse_iso8601(text)
    if dt is None:
        _exit_with_error(
            message=(
                "Invalid --since timestamp. Expected ISO8601 "
                "(example: 2026-02-01T00:00:00Z)"
            ),
            error_code="invalid_since",
            exit_code=2,
            json_output=json_output,
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _normalize_choice_option(value: str, option_name: str, allowed: Sequence[str]) -> str:
    normalized = str(value).strip().lower()
    allowed_values = [str(item).strip().lower() for item in allowed if str(item).strip()]
    if normalized not in allowed_values:
        typer.echo(
            f"Invalid {option_name} value '{value}'. Expected one of: "
            f"{', '.join(allowed_values)}"
        )
        raise typer.Exit(code=2)
    return normalized


def _option_provided(ctx: typer.Context | None, param_name: str) -> bool:
    if ctx is None:
        return False
    source = ctx.get_parameter_source(param_name)
    return source == ParameterSource.COMMANDLINE


def _load_config_or_exit() -> dict[str, Any]:
    raw_path = os.environ.get("FLEETMDM_CONFIG", DEFAULT_CONFIG_PATH)
    config_path = Path(os.path.expanduser(raw_path))
    if not config_path.exists():
        return {}

    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        console.print(f"[red]Invalid config file {config_path}: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    if payload is None:
        return {}
    if not isinstance(payload, dict):
        console.print(f"[red]Invalid config file {config_path}: root must be a mapping[/red]")
        raise typer.Exit(code=2)
    return payload


def _config_mapping(payload: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        console.print(f"[red]Invalid config value for '{key}': expected a mapping[/red]")
        raise typer.Exit(code=2)
    return dict(value)


def _config_string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        console.print(f"[red]Invalid config value for '{key}': expected a non-empty string[/red]")
        raise typer.Exit(code=2)
    return value.strip()


def _config_non_negative_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        console.print(
            f"[red]Invalid config value for '{key}': expected a non-negative integer[/red]"
        )
        raise typer.Exit(code=2)
    return int(value)


def _resolve_db_path_with_defaults(db: str | None) -> Path:
    if db is not None:
        return resolve_db_path(db)

    config = _load_config_or_exit()
    configured_db = _config_string(config, "db")
    return resolve_db_path(configured_db)


def _resolve_report_defaults(
    *,
    format: str,
    sort_by: str,
    top: int,
    sarif_max_failures_per_policy: int,
    ctx: typer.Context | None,
) -> tuple[str, str, int, int]:
    use_config = not (
        _option_provided(ctx, "format")
        and _option_provided(ctx, "sort_by")
        and _option_provided(ctx, "top")
        and _option_provided(ctx, "sarif_max_failures_per_policy")
    )
    if not use_config:
        return format, sort_by, top, sarif_max_failures_per_policy

    config = _load_config_or_exit()
    report_defaults = _config_mapping(config, "report")

    resolved_format = (
        format
        if _option_provided(ctx, "format")
        else _config_string(report_defaults, "format") or format
    )
    resolved_sort_by = (
        sort_by
        if _option_provided(ctx, "sort_by")
        else _config_string(report_defaults, "sort_by") or sort_by
    )
    configured_top = (
        _config_non_negative_int(report_defaults, "top")
        if report_defaults.get("top") is not None
        else None
    )
    resolved_top = (
        top
        if _option_provided(ctx, "top")
        else configured_top
        if configured_top is not None
        else top
    )
    configured_sarif_limit = (
        _config_non_negative_int(report_defaults, "sarif_max_failures_per_policy")
        if report_defaults.get("sarif_max_failures_per_policy") is not None
        else None
    )
    resolved_sarif_limit = (
        sarif_max_failures_per_policy
        if _option_provided(ctx, "sarif_max_failures_per_policy")
        else configured_sarif_limit
        if configured_sarif_limit is not None
        else sarif_max_failures_per_policy
    )
    return resolved_format, resolved_sort_by, resolved_top, resolved_sarif_limit


def _resolve_evidence_export_defaults(
    *,
    output: Path | None,
    redaction_profile: str,
    history_limit: int,
    ctx: typer.Context | None,
) -> tuple[Path | None, str, int]:
    use_config = not (
        _option_provided(ctx, "output")
        and _option_provided(ctx, "redaction_profile")
        and _option_provided(ctx, "history_limit")
    )
    if not use_config:
        return output, redaction_profile, history_limit

    config = _load_config_or_exit()
    evidence_defaults = _config_mapping(config, "evidence_export")

    resolved_output = output
    if not _option_provided(ctx, "output"):
        configured_output = _config_string(evidence_defaults, "output")
        if configured_output:
            resolved_output = Path(configured_output)

    resolved_profile = (
        redaction_profile
        if _option_provided(ctx, "redaction_profile")
        else _config_string(evidence_defaults, "redaction_profile") or redaction_profile
    )
    configured_history_limit = (
        _config_non_negative_int(evidence_defaults, "history_limit")
        if evidence_defaults.get("history_limit") is not None
        else None
    )
    resolved_history_limit = (
        history_limit
        if _option_provided(ctx, "history_limit")
        else configured_history_limit
        if configured_history_limit is not None
        else history_limit
    )
    return resolved_output, resolved_profile, resolved_history_limit


def _doctor_snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    sqlite_version = str(conn.execute("SELECT sqlite_version()").fetchone()[0])
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
    synchronous = str(conn.execute("PRAGMA synchronous").fetchone()[0])

    tables = {
        "devices": int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]),
        "device_facts": int(conn.execute("SELECT COUNT(*) FROM device_facts").fetchone()[0]),
        "policies": int(conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]),
        "policy_assignments": int(
            conn.execute("SELECT COUNT(*) FROM policy_assignments").fetchone()[0]
        ),
        "policy_tag_assignments": int(
            conn.execute("SELECT COUNT(*) FROM policy_tag_assignments").fetchone()[0]
        ),
        "scripts": int(conn.execute("SELECT COUNT(*) FROM scripts").fetchone()[0]),
        "compliance_runs": int(conn.execute("SELECT COUNT(*) FROM compliance_runs").fetchone()[0]),
        "compliance_results": int(
            conn.execute("SELECT COUNT(*) FROM compliance_results").fetchone()[0]
        ),
    }
    indexes = [
        str(row["name"])
        for row in conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
    ]
    return {
        "sqlite_version": sqlite_version,
        "pragmas": {
            "page_size": page_size,
            "page_count": page_count,
            "freelist_count": freelist_count,
            "journal_mode": journal_mode,
            "synchronous": synchronous,
        },
        "tables": tables,
        "indexes": indexes,
    }


def _keyring_manifest_path(keyring_dir: Path) -> Path:
    return keyring_dir / "keyring.json"


def _load_keyring_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("keyring.json must be a JSON object")
    keys = payload.get("keys", [])
    if not isinstance(keys, list):
        raise ValueError("keyring.json keys must be a list")
    normalized: list[dict[str, Any]] = []
    for entry in keys:
        if not isinstance(entry, dict):
            raise ValueError("keyring.json keys entries must be objects")
        key_id = str(entry.get("key_id", "")).strip()
        filename = str(entry.get("filename", "")).strip()
        if not key_id or not filename:
            raise ValueError("keyring.json keys entries require key_id and filename")
        normalized.append(
            {
                "key_id": key_id,
                "filename": filename,
                "status": str(entry.get("status", "active")).strip().lower() or "active",
                "created_at": entry.get("created_at"),
                "activated_at": entry.get("activated_at"),
                "revoked_at": entry.get("revoked_at"),
            }
        )
    payload["schema_version"] = int(payload.get("schema_version", 1) or 1)
    payload["keys"] = sorted(normalized, key=lambda item: str(item.get("key_id", "")))
    return payload


def _save_keyring_manifest(path: Path, payload: dict[str, Any]) -> None:
    payload = dict(payload)
    payload.setdefault("schema_version", 1)
    keys = payload.get("keys", [])
    if isinstance(keys, list):
        payload["keys"] = sorted(keys, key=lambda item: str(item.get("key_id", "")))
    path.write_text(_json_payload_text(payload), encoding="utf-8")


def _load_redact_config(path: Path) -> dict[str, Any]:
    raw_bytes = path.read_bytes()
    text = raw_bytes.decode("utf-8")
    try:
        payload: Any = json.loads(text)
    except ValueError:
        payload = yaml.safe_load(text)

    if not isinstance(payload, dict):
        raise ValueError("redact config must be a YAML/JSON object")

    allowlist = payload.get("facts_allowlist", [])
    denylist = payload.get("facts_denylist", [])
    replacement = payload.get("replacement", "[REDACTED]")

    if allowlist is not None and not isinstance(allowlist, list):
        raise ValueError("facts_allowlist must be a list of dot-path strings")
    if denylist is not None and not isinstance(denylist, list):
        raise ValueError("facts_denylist must be a list of dot-path strings")
    if not isinstance(replacement, str):
        raise ValueError("replacement must be a string")

    def normalize_paths(value: Any) -> list[str]:
        paths: list[str] = []
        if not value:
            return paths
        for item in value:
            path = str(item).strip()
            if not path or path.startswith(".") or path.endswith(".") or ".." in path:
                raise ValueError(f"Invalid dot-path: {item!r}")
            paths.append(path)
        return paths

    return {
        "facts_allowlist": normalize_paths(allowlist),
        "facts_denylist": normalize_paths(denylist),
        "replacement": replacement,
        "config_sha256": _hash_bytes(raw_bytes),
    }


def _get_dot_path(source: Any, dot_path: str) -> tuple[bool, Any]:
    current: Any = source
    for part in dot_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _set_dot_path(target: dict[str, Any], dot_path: str, value: Any) -> None:
    parts = dot_path.split(".")
    current: dict[str, Any] = target
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def _redact_inventory_facts(
    inventory: Sequence[dict[str, Any]], redact_config: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if not redact_config:
        return [dict(row) for row in inventory]

    allowlist = list(redact_config.get("facts_allowlist", []))
    denylist = list(redact_config.get("facts_denylist", []))
    replacement = redact_config.get("replacement", "[REDACTED]")

    redacted: list[dict[str, Any]] = []
    for record in inventory:
        row = dict(record)
        facts = row.get("facts")
        if not isinstance(facts, dict):
            facts = {}

        if allowlist:
            filtered: dict[str, Any] = {}
            for path in allowlist:
                found, value = _get_dot_path(facts, path)
                if found:
                    _set_dot_path(filtered, path, value)
            facts = filtered

        for path in denylist:
            found, _value = _get_dot_path(facts, path)
            if found:
                _set_dot_path(facts, path, replacement)

        row["facts"] = facts
        redacted.append(row)
    return redacted


def _strip_yaml_comment_only_lines(raw_yaml: str) -> str:
    lines: list[str] = []
    for line in raw_yaml.splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


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
    db_path = _resolve_db_path_with_defaults(db)
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
    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        for device in devices:
            if not device.get("last_seen"):
                device["last_seen"] = utc_now()
        count = ingest_devices(conn, devices)
    console.print(f"Ingested {count} device(s)")


@app.command()
def export(
    output: Path | None = OPT_OUTPUT,
    db: str | None = OPT_DB,
) -> None:
    """Export inventory as JSON."""
    db_path = _resolve_db_path_with_defaults(db)
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


@policy_app.command("lint")
def policy_lint(
    path: Path = ARG_POLICY_PATH,
    recursive: bool = typer.Option(
        False,
        "--recursive",
        help="When PATH is a directory, lint YAML files recursively",
    ),
    format: str = typer.Option("text", "--format", help="text/json"),
) -> None:
    """Lint policy files for schema + semantic issues without mutating the DB."""
    normalized_format = _normalize_choice_option(format, "--format", ("text", "json"))
    json_output = normalized_format == "json"

    paths = _iter_policy_lint_paths(path, recursive=recursive)
    if not paths:
        _exit_with_error(
            message="No policy files found",
            error_code="policy_files_not_found",
            exit_code=1,
            json_output=json_output,
            details={"path": str(path), "recursive": recursive},
        )

    results = [_lint_policy_file(candidate) for candidate in paths]
    has_errors = any(not bool(item.get("ok")) for item in results)

    if json_output:
        payload = {
            "schema_version": 1,
            "path": str(path),
            "recursive": recursive,
            "count": len(results),
            "ok": not has_errors,
            "results": results,
        }
        if has_errors:
            payload["error"] = {
                "code": "policy_lint_failed",
                "message": "One or more policy files failed lint checks",
            }
        typer.echo(_json_payload_text(payload), nl=False)
        if has_errors:
            raise typer.Exit(code=1)
        return

    for item in results:
        status = "OK" if item["ok"] else "FAIL"
        warnings = list(item.get("warnings", []))
        if item["ok"] and warnings:
            status = "WARN"
        policy_id = item.get("policy_id")
        label = f"{status}: {item['path']}"
        if policy_id:
            label += f" (policy_id={policy_id})"
        console.print(label)
        for warning in warnings:
            console.print(f"  warning: {warning}")
        for error in item.get("errors", []):
            console.print(f"  error: {error}")

    if has_errors:
        raise typer.Exit(code=1)


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

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        add_policy(conn, policy.id, policy.name, policy.description, raw_yaml)
    console.print(f"Saved policy {policy.id}")


@policy_app.command("list")
def policy_list(
    db: str | None = OPT_DB,
) -> None:
    """List policies."""
    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
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

    db_path = _resolve_db_path_with_defaults(db)
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

    db_path = _resolve_db_path_with_defaults(db)
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
    unmatched_tags: bool = typer.Option(
        False,
        "--unmatched-tags",
        help="Show tag assignments that currently match zero devices",
    ),
    db: str | None = OPT_DB,
) -> None:
    """Show policy assignments for a device, tag, or stale tag assignments."""
    if unmatched_tags and (device_id is not None or tag is not None):
        console.print("[red]--unmatched-tags cannot be combined with --device or --tag[/red]")
        raise typer.Exit(code=2)
    if not unmatched_tags and (device_id is None) == (tag is None):
        console.print("Provide exactly one of --device or --tag")
        raise typer.Exit(code=2)

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        name_map = _policy_name_map(conn)
        if unmatched_tags:
            tags_by_device = _device_tags_by_id(conn)
            known_tags = {tag_name for tags in tags_by_device.values() for tag_name in tags}

            stale_rows: list[dict[str, str]] = []
            for row in list_all_policy_tag_assignments(conn):
                policy_id_value = str(row["policy_id"])
                assigned_tag = _normalize_tag(str(row["tag"]))
                if assigned_tag in known_tags:
                    continue
                stale_rows.append(
                    {
                        "tag": assigned_tag,
                        "policy_id": policy_id_value,
                        "policy_name": name_map.get(policy_id_value, ""),
                    }
                )

            table = Table(title="Unmatched Tag Assignments")
            table.add_column("Tag")
            table.add_column("Policy ID")
            table.add_column("Name")
            if stale_rows:
                for row in sorted(
                    stale_rows,
                    key=lambda item: (
                        item["tag"].casefold(),
                        item["policy_id"].casefold(),
                    ),
                ):
                    table.add_row(row["tag"], row["policy_id"], row["policy_name"])
            else:
                table.add_row("(none)", "", "")
            console.print(table)
            return

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
    normalized_format = _normalize_choice_option(
        format,
        "--format",
        ("table", "json", "csv"),
    )
    json_output = normalized_format == "json"
    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        assignment_mode = has_any_policy_assignments(conn)
        policy_rows = list_policies(conn)
        all_policy_ids = [str(row["policy_id"]) for row in policy_rows]
        run_id = create_compliance_run(conn)
        devices = [row["device_id"] for row in list_devices(conn)]
        if device_id:
            if not device_exists(conn, device_id):
                _exit_with_error(
                    message=f"Unknown device: {device_id}",
                    error_code="device_not_found",
                    json_output=json_output,
                    details={"device_id": device_id},
                )
            devices = [device_id]

        if not devices:
            _exit_with_error(
                message="No devices found",
                error_code="no_devices_found",
                json_output=json_output,
            )

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
                    _exit_with_error(
                        message=(
                            f"No policies assigned to {did} "
                            "(device assignments or matching tag assignments)"
                        ),
                        error_code="no_assigned_policies",
                        json_output=json_output,
                        details={"device_id": did},
                    )
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
                    _exit_with_error(
                        message="No policies to evaluate",
                        error_code="no_policies_to_evaluate",
                        json_output=json_output,
                        details={"device_id": did},
                    )
                continue

            results_payload.append({"device_id": did, "results": policy_results})

    if not results_payload:
        _exit_with_error(
            message="No policies to evaluate",
            error_code="no_policies_to_evaluate",
            json_output=json_output,
        )

    if normalized_format == "table":
        if len(results_payload) > 1:
            console.print("Table format requires --device")
            raise typer.Exit(code=1)
        console.print(render_table(results_payload[0]["results"]))
        return
    if normalized_format == "json":
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
    if normalized_format == "csv":
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["device_id", "policy_id", "policy_name", "status", "failed_checks"])
        for entry in results_payload:
            did = csv_safe_cell(entry["device_id"])
            for result in entry["results"]:
                failed = [check.message for check in result.checks if not check.passed]
                writer.writerow(
                    [
                        did,
                        csv_safe_cell(result.policy_id),
                        csv_safe_cell(result.policy_name),
                        "PASS" if result.passed else "FAIL",
                        csv_safe_cell("; ".join(failed)),
                    ]
                )
        console.print(buffer.getvalue().rstrip("\n"))
        return


@app.command()
def report(
    ctx: typer.Context,
    format: str = typer.Option("table", "--format", help="table/json/csv/junit/sarif"),
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    policy_id: str | None = OPT_POLICY_ID_OPTIONAL,
    sort_by: str = typer.Option("name", "--sort-by", help="name|failed|passed"),
    top: int = typer.Option(
        0, "--top", min=0, help="Limit rows after sorting (0 means all rows)"
    ),
    sarif_max_failures_per_policy: int = typer.Option(
        0,
        "--sarif-max-failures-per-policy",
        min=0,
        help="For SARIF only: include up to N failed device IDs per policy result (0 disables)",
    ),
    only_assigned: bool = typer.Option(
        False,
        "--only-assigned",
        help="Evaluate only assigned policies, even when no assignments exist",
    ),
    only_failing: bool = typer.Option(
        False, "--only-failing", help="Include only policies with at least one failing device"
    ),
    only_skipped: bool = typer.Option(
        False,
        "--only-skipped",
        help="Include only policies with no applicable devices (passed=0, failed=0)",
    ),
    db: str | None = OPT_DB,
) -> None:
    """Summary compliance report across devices."""
    (
        resolved_format,
        resolved_sort_by,
        resolved_top,
        resolved_sarif_limit,
    ) = _resolve_report_defaults(
        format=format,
        sort_by=sort_by,
        top=top,
        sarif_max_failures_per_policy=sarif_max_failures_per_policy,
        ctx=ctx,
    )
    normalized_format = _normalize_choice_option(
        resolved_format,
        "--format",
        ("table", "json", "csv", "junit", "sarif"),
    )
    json_output = normalized_format == "json"
    normalized_sort_by = (resolved_sort_by or "").strip().lower()
    if normalized_sort_by not in {"name", "failed", "passed"}:
        _exit_with_error(
            message="Invalid --sort-by value. Expected one of: name, failed, passed",
            error_code="invalid_sort_by",
            exit_code=2,
            json_output=json_output,
            details={"allowed_values": ["name", "failed", "passed"]},
        )

    if only_failing and only_skipped:
        _exit_with_error(
            message="Options --only-failing and --only-skipped are mutually exclusive",
            error_code="mutually_exclusive_filters",
            json_output=json_output,
            details={"options": ["only_failing", "only_skipped"]},
        )

    normalized_device_id = (device_id or "").strip() or None
    normalized_policy_id = (policy_id or "").strip() or None

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        assignment_mode = has_any_policy_assignments(conn) or only_assigned
        if normalized_policy_id:
            policy_row = get_policy(conn, normalized_policy_id)
            if policy_row is None:
                _exit_with_error(
                    message=f"Policy not found: {normalized_policy_id}",
                    error_code="policy_not_found",
                    json_output=json_output,
                    details={"policy_id": normalized_policy_id},
                )
            policy_rows = [policy_row]
        else:
            policy_rows = list_policies(conn)

        if normalized_device_id:
            device_row = get_device(conn, normalized_device_id)
            if device_row is None:
                _exit_with_error(
                    message=f"Device not found: {normalized_device_id}",
                    error_code="device_not_found",
                    json_output=json_output,
                    details={"device_id": normalized_device_id},
                )
            device_rows = [device_row]
        else:
            device_rows = list_devices(conn)

        if not policy_rows or not device_rows:
            _exit_with_error(
                message="No data to report",
                error_code="no_report_data",
                json_output=json_output,
            )

        summary: dict[str, dict[str, Any]] = {}
        sarif_context: dict[str, dict[str, Any]] = {}
        for policy in policy_rows:
            policy_id_value = str(policy["policy_id"])
            summary[policy_id_value] = {
                "policy_id": policy_id_value,
                "policy_name": str(policy["name"]),
                "passed_count": 0,
                "failed_count": 0,
            }
            sarif_context[policy_id_value] = {
                "policy_description": str(policy["description"] or "").strip(),
                "failed_devices": [],
            }
        selected_policy_ids = {str(policy["policy_id"]) for policy in policy_rows}

        for device in device_rows:
            facts = get_device_facts(conn, device["device_id"]) or {}
            device_data = dict(device)
            evaluation_context = _build_evaluation_context(device_data, facts)
            tags = _extract_device_tags(facts)
            applicable = resolve_assigned_policies_for_device(conn, device["device_id"], tags)
            if not assignment_mode:
                applicable = [str(row["policy_id"]) for row in policy_rows]
            if assignment_mode and not applicable:
                continue
            for pid in applicable:
                pid_text = str(pid)
                if pid_text not in selected_policy_ids:
                    continue
                raw_yaml = get_policy_yaml(conn, pid_text)
                if not raw_yaml:
                    continue
                policy = load_policy(raw_yaml)
                if not policy_matches_targets(policy, device_data, facts):
                    continue
                result = evaluate_policy(policy, evaluation_context)
                if result.passed:
                    summary[pid_text]["passed_count"] += 1
                else:
                    summary[pid_text]["failed_count"] += 1
                    sarif_context[pid_text]["failed_devices"].append(str(device["device_id"]))

    filtered = list(summary.values())
    if only_failing:
        filtered = [row for row in filtered if int(row.get("failed_count", 0) or 0) > 0]
    elif only_skipped:
        filtered = [
            row
            for row in filtered
            if int(row.get("failed_count", 0) or 0) == 0
            and int(row.get("passed_count", 0) or 0) == 0
        ]

    if normalized_sort_by == "failed":
        filtered.sort(
            key=lambda row: (
                -int(row.get("failed_count", 0) or 0),
                -int(row.get("passed_count", 0) or 0),
                str(row.get("policy_name", "")).casefold(),
                str(row.get("policy_id", "")).casefold(),
            )
        )
    elif normalized_sort_by == "passed":
        filtered.sort(
            key=lambda row: (
                -int(row.get("passed_count", 0) or 0),
                int(row.get("failed_count", 0) or 0),
                str(row.get("policy_name", "")).casefold(),
                str(row.get("policy_id", "")).casefold(),
            )
        )
    else:
        filtered.sort(
            key=lambda row: (
                str(row.get("policy_name", "")).casefold(),
                str(row.get("policy_id", "")).casefold(),
            )
        )

    if resolved_top > 0:
        filtered = filtered[:resolved_top]

    if normalized_format == "json":
        console.print(json.dumps(filtered, indent=2))
        return
    if normalized_format == "csv":
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["policy_id", "policy_name", "passed", "failed"])
        for row in filtered:
            writer.writerow(
                [
                    csv_safe_cell(row["policy_id"]),
                    csv_safe_cell(row["policy_name"]),
                    row["passed_count"],
                    row["failed_count"],
                ]
            )
        console.print(buffer.getvalue().rstrip("\n"))
        return
    if normalized_format == "junit":
        typer.echo(render_junit_summary(filtered), nl=False)
        return
    if normalized_format == "sarif":
        sarif_rows: list[dict[str, Any]] = []
        for row in filtered:
            context = sarif_context.get(str(row["policy_id"]), {})
            sarif_rows.append(
                {
                    **row,
                    "policy_description": str(context.get("policy_description", "") or "").strip(),
                    "failed_devices": list(context.get("failed_devices", [])),
                }
            )
        typer.echo(
            render_sarif_summary(
                sarif_rows, max_failures_per_policy=resolved_sarif_limit
            ),
            nl=False,
        )
        return

    table = Table(title="Compliance Summary")
    table.add_column("Policy")
    table.add_column("Pass")
    table.add_column("Fail")
    for row in filtered:
        table.add_row(row["policy_name"], str(row["passed_count"]), str(row["failed_count"]))
    console.print(table)


@app.command()
def history(
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    policy_id: str | None = OPT_POLICY_ID_OPTIONAL,
    since: str | None = OPT_SINCE,
    limit: int = OPT_LIMIT,
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Show compliance history."""
    normalized_format = _normalize_choice_option(
        format,
        "--format",
        ("table", "json", "csv"),
    )
    normalized_since = _normalize_since_option(
        since,
        json_output=normalized_format == "json",
    )
    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        rows = list_compliance_history(conn, device_id, policy_id, limit, since=normalized_since)

    if normalized_format == "json":
        console.print(json.dumps([dict(row) for row in rows], indent=2))
        return
    if normalized_format == "csv":
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "run_id",
                "device_id",
                "policy_id",
                "policy_name",
                "status",
                "failed_checks",
                "checked_at",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    csv_safe_cell(row["run_id"]),
                    csv_safe_cell(row["device_id"]),
                    csv_safe_cell(row["policy_id"]),
                    csv_safe_cell(row["policy_name"]),
                    csv_safe_cell(row["status"]),
                    csv_safe_cell(row["failed_checks"]),
                    csv_safe_cell(row["checked_at"]),
                ]
            )
        console.print(buffer.getvalue().rstrip("\n"))
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
    policy_id: str | None = OPT_POLICY_ID_OPTIONAL,
    device_id: str | None = OPT_DEVICE_OPTIONAL,
    since: str | None = OPT_SINCE,
    include_new_missing: bool = typer.Option(
        False,
        "--include-new-missing",
        help="Include rows that are present in only one of the two runs",
    ),
    format: str = typer.Option("table", "--format", help="table/json/csv"),
    db: str | None = OPT_DB,
) -> None:
    """Compare the last two compliance runs and show status changes."""
    normalized_format = _normalize_choice_option(
        format,
        "--format",
        ("table", "json", "csv"),
    )
    normalized_policy_id = (policy_id or "").strip() or None
    normalized_device_id = (device_id or "").strip() or None
    json_output = normalized_format == "json"
    normalized_since = _normalize_since_option(since, json_output=json_output)

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        runs = list_recent_runs(conn, 2, since=normalized_since)
        if len(runs) < 2:
            _exit_with_error(
                message="Need at least two compliance runs to calculate drift",
                error_code="insufficient_runs",
                json_output=json_output,
                details={"required_runs": 2, "available_runs": len(runs)},
            )
        latest_run = runs[0]["run_id"]
        previous_run = runs[1]["run_id"]
        latest = list_results_for_run(
            conn, latest_run, policy_id=normalized_policy_id, device_id=normalized_device_id
        )
        previous = list_results_for_run(
            conn,
            previous_run,
            policy_id=normalized_policy_id,
            device_id=normalized_device_id,
        )
    changes = _compute_drift_changes(
        latest, previous, include_new_missing=include_new_missing
    )

    if normalized_format == "json":
        console.print(json.dumps(changes, indent=2))
        return
    if normalized_format == "csv":
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["device_id", "policy_id", "policy_name", "change", "previous", "current"])
        for row in changes:
            writer.writerow(
                [
                    csv_safe_cell(row["device_id"]),
                    csv_safe_cell(row["policy_id"]),
                    csv_safe_cell(row.get("policy_name", "")),
                    csv_safe_cell(row.get("change_type", "changed")),
                    csv_safe_cell(row["previous"]),
                    csv_safe_cell(row["current"]),
                ]
            )
        console.print(buffer.getvalue().rstrip("\n"))
        return

    table = Table(title="Compliance Drift (last two runs)")
    table.add_column("Device")
    table.add_column("Policy")
    table.add_column("Change")
    table.add_column("Previous")
    table.add_column("Current")
    if not changes:
        table.add_row("(none)", "", "", "", "")
    else:
        for row in changes:
            policy_name = (row.get("policy_name") or "").strip()
            policy_id_value = row["policy_id"]
            policy_label = policy_id_value
            if policy_name and policy_name != policy_id_value:
                policy_label = f"{policy_name} ({policy_id_value})"
            elif policy_name:
                policy_label = policy_name
            table.add_row(
                row["device_id"],
                policy_label,
                row.get("change_type", "changed"),
                row["previous"],
                row["current"],
            )
    console.print(table)


@app.command()
def doctor(
    format: str = typer.Option("table", "--format", help="table/json"),
    integrity_check: bool = typer.Option(
        False,
        "--integrity-check",
        help="Run PRAGMA integrity_check and include the result",
    ),
    vacuum: bool = typer.Option(
        False,
        "--vacuum",
        help="Run VACUUM before reporting stats",
    ),
    db: str | None = OPT_DB,
) -> None:
    """Show DB stats and common misconfiguration signals."""
    normalized_format = _normalize_choice_option(format, "--format", ("table", "json"))

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)

    warnings: list[str] = []
    db_size_bytes_before = 0
    db_size_bytes_after = 0
    if db_path.exists():
        try:
            db_size_bytes_before = int(db_path.stat().st_size)
            db_size_bytes_after = db_size_bytes_before
        except OSError as exc:
            warnings.append(f"Unable to stat DB file: {exc}")

    snapshot_before: dict[str, Any] = {
        "sqlite_version": "",
        "pragmas": {
            "page_size": 0,
            "page_count": 0,
            "freelist_count": 0,
            "journal_mode": "",
            "synchronous": "",
        },
        "tables": {},
        "indexes": [],
    }
    snapshot_after = dict(snapshot_before)

    integrity_messages: list[str] = []
    integrity_ok: bool | None = None
    vacuum_executed = False
    vacuum_skipped_reason: str | None = None

    with connect(db_path) as conn:
        snapshot_before = _doctor_snapshot(conn)

        if integrity_check:
            try:
                rows = conn.execute("PRAGMA integrity_check").fetchall()
                integrity_messages = [
                    str(row[0]).strip() for row in rows if row and row[0] is not None
                ]
                if not integrity_messages:
                    integrity_messages = ["(no output)"]
                integrity_ok = (
                    len(integrity_messages) == 1
                    and integrity_messages[0].strip().lower() == "ok"
                )
                if not integrity_ok:
                    warnings.append(
                        f"Integrity check reported {len(integrity_messages)} issue message(s)."
                    )
            except sqlite3.DatabaseError as exc:
                integrity_ok = False
                integrity_messages = [f"error: {exc}"]
                warnings.append(f"Integrity check failed: {exc}")

        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            warnings.append(f"Foreign key check found {len(fk_issues)} issue(s).")

        if vacuum:
            freelist_before = int(snapshot_before["pragmas"]["freelist_count"])
            if freelist_before <= 0:
                vacuum_skipped_reason = "no free pages"
                warnings.append("No free pages detected; VACUUM skipped.")
            else:
                try:
                    conn.commit()
                    conn.execute("VACUUM")
                    vacuum_executed = True
                except sqlite3.DatabaseError as exc:
                    warnings.append(f"VACUUM failed: {exc}")
        snapshot_after = _doctor_snapshot(conn)

    if db_path.exists():
        try:
            db_size_bytes_after = int(db_path.stat().st_size)
        except OSError as exc:
            warnings.append(f"Unable to stat DB file after maintenance: {exc}")

    page_count = int(snapshot_after["pragmas"]["page_count"])
    freelist_count = int(snapshot_after["pragmas"]["freelist_count"])
    if freelist_count > 0 and page_count > 0:
        ratio = freelist_count / page_count
        if ratio >= 0.25:
            warnings.append(
                f"High freelist ratio ({freelist_count}/{page_count}); consider running "
                "`fleetmdm doctor --vacuum`."
            )

    payload: dict[str, Any] = {
        "schema_version": 1,
        "db_path": str(db_path),
        "db_size_bytes": db_size_bytes_after,
        "sqlite_version": snapshot_after["sqlite_version"],
        "pragmas": dict(snapshot_after["pragmas"]),
        "tables": dict(snapshot_after["tables"]),
        "indexes": list(snapshot_after["indexes"]),
        "maintenance": {
            "integrity_check": {
                "requested": integrity_check,
                "ok": integrity_ok,
                "messages": integrity_messages,
            },
            "vacuum": {
                "requested": vacuum,
                "executed": vacuum_executed,
                "skipped_reason": vacuum_skipped_reason,
                "page_count_before": int(snapshot_before["pragmas"]["page_count"]),
                "page_count_after": page_count,
                "freelist_count_before": int(snapshot_before["pragmas"]["freelist_count"]),
                "freelist_count_after": freelist_count,
                "db_size_bytes_before": db_size_bytes_before,
                "db_size_bytes_after": db_size_bytes_after,
                "db_size_reclaimed_bytes": (
                    max(0, db_size_bytes_before - db_size_bytes_after)
                    if vacuum_executed
                    else 0
                ),
            },
        },
        "warnings": warnings,
    }

    if normalized_format == "json":
        typer.echo(json.dumps(payload, indent=2))
        return

    table = Table(title="FleetMDM Doctor")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("DB", payload["db_path"])
    table.add_row("Size (bytes)", str(payload["db_size_bytes"]))
    table.add_row("SQLite", payload["sqlite_version"])
    table.add_row("Journal", payload["pragmas"]["journal_mode"])
    table.add_row("Synchronous", payload["pragmas"]["synchronous"])
    table.add_row(
        "Pages",
        f"{payload['pragmas']['page_count']} @ {payload['pragmas']['page_size']} bytes",
    )
    table.add_row("Freelist", str(payload["pragmas"]["freelist_count"]))
    integrity_state = "not requested"
    if integrity_check:
        integrity_state = "ok" if integrity_ok else "issues detected"
    table.add_row("Integrity Check", integrity_state)
    vacuum_state = "not requested"
    if vacuum:
        if vacuum_executed:
            vacuum_state = "executed"
        elif vacuum_skipped_reason:
            vacuum_state = f"skipped ({vacuum_skipped_reason})"
        else:
            vacuum_state = "failed"
        table.add_row(
            "Vacuum Freelist",
            (
                f"{payload['maintenance']['vacuum']['freelist_count_before']} -> "
                f"{payload['maintenance']['vacuum']['freelist_count_after']}"
            ),
        )
        table.add_row(
            "Vacuum Size (bytes)",
            (
                f"{payload['maintenance']['vacuum']['db_size_bytes_before']} -> "
                f"{payload['maintenance']['vacuum']['db_size_bytes_after']}"
            ),
        )
        table.add_row(
            "Vacuum Reclaimed",
            str(payload["maintenance"]["vacuum"]["db_size_reclaimed_bytes"]),
        )
    table.add_row("Vacuum", vacuum_state)
    for name, count in payload["tables"].items():
        table.add_row(f"Table: {name}", str(count))
    table.add_row("Indexes", str(len(payload["indexes"])))
    console.print(table)

    if integrity_check and integrity_messages:
        console.print("\nIntegrity Check Output:")
        max_messages = 5
        for msg in integrity_messages[:max_messages]:
            console.print(f"- {msg}")
        if len(integrity_messages) > max_messages:
            console.print(f"- ... ({len(integrity_messages) - max_messages} more)")

    if warnings:
        console.print("\nWarnings:")
        for msg in warnings:
            console.print(f"- {msg}")


@evidence_key_app.command("list")
def evidence_key_list(
    keyring_dir: Path = OPT_KEYRING_DIR,
    format: str = typer.Option("table", "--format", help="table/json"),
) -> None:
    """List signing keys in a keyring (using keyring.json when present)."""
    normalized_format = _normalize_choice_option(format, "--format", ("table", "json"))

    manifest_path = _keyring_manifest_path(keyring_dir)
    warnings: list[str] = []
    keys: list[dict[str, Any]] = []

    if manifest_path.exists():
        try:
            manifest = _load_keyring_manifest(manifest_path)
        except (OSError, ValueError) as exc:
            console.print(f"[red]Invalid keyring manifest: {exc}[/red]")
            raise typer.Exit(code=1) from exc
        for entry in manifest.get("keys", []):
            if not isinstance(entry, dict):
                continue
            keys.append(dict(entry))
    else:
        warnings.append("keyring.json not found; listing keys by scanning directory")
        for candidate in sorted(keyring_dir.iterdir()):
            if not candidate.is_file():
                continue
            try:
                if candidate.stat().st_size > 64 * 1024:
                    continue
                candidate_bytes = candidate.read_bytes()
            except OSError:
                continue
            keys.append(
                {
                    "key_id": _key_id_for_bytes(candidate_bytes),
                    "filename": candidate.name,
                    "status": "unknown",
                    "created_at": None,
                    "activated_at": None,
                    "revoked_at": None,
                }
            )

    if normalized_format == "json":
        payload = {
            "schema_version": 1,
            "keyring_dir": str(keyring_dir),
            "warnings": warnings,
            "keys": sorted(keys, key=lambda item: str(item.get("key_id", ""))),
        }
        typer.echo(_json_payload_text(payload), nl=False)
        return

    table = Table(title=f"Signing Keys ({keyring_dir})")
    table.add_column("Key ID")
    table.add_column("Status")
    table.add_column("Filename")
    table.add_column("Activated")
    table.add_column("Revoked")
    if not keys:
        table.add_row("(none)", "", "", "", "")
    else:
        for entry in sorted(keys, key=lambda item: str(item.get("key_id", ""))):
            table.add_row(
                str(entry.get("key_id", "")),
                str(entry.get("status", "")),
                str(entry.get("filename", "")),
                str(entry.get("activated_at") or ""),
                str(entry.get("revoked_at") or ""),
            )
    console.print(table)
    for warning in warnings:
        console.print(f"[yellow]{warning}[/yellow]")


@evidence_key_app.command("revoke")
def evidence_key_revoke(
    key_id: str = typer.Argument(..., help="Key ID to revoke"),
    keyring_dir: Path = OPT_KEYRING_DIR,
) -> None:
    """Mark a signing key as revoked in keyring.json (does not delete key material)."""
    desired = key_id.strip()
    if not desired:
        console.print("[red]key_id cannot be empty[/red]")
        raise typer.Exit(code=2)

    manifest_path = _keyring_manifest_path(keyring_dir)
    if not manifest_path.exists():
        console.print("[red]keyring.json not found; cannot revoke without a manifest[/red]")
        raise typer.Exit(code=1)

    try:
        manifest = _load_keyring_manifest(manifest_path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Invalid keyring manifest: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    now = datetime.now(timezone.utc).isoformat()
    found = False
    updated: list[dict[str, Any]] = []
    for entry in manifest.get("keys", []):
        if not isinstance(entry, dict):
            continue
        row = dict(entry)
        if str(row.get("key_id", "")).strip() == desired:
            found = True
            row["status"] = "revoked"
            row["revoked_at"] = now
        updated.append(row)

    if not found:
        console.print(f"[red]No key found in manifest for key_id={desired}[/red]")
        raise typer.Exit(code=1)

    manifest["keys"] = updated
    manifest["updated_at"] = now
    _save_keyring_manifest(manifest_path, manifest)
    console.print(f"Revoked key {desired} in {manifest_path}")


@evidence_app.command("keygen")
def evidence_keygen(
    output: Path | None = OPT_EVIDENCE_KEY_OUTPUT,
    keyring_dir: Path | None = OPT_KEYRING_DIR_CREATE,
    force: bool = OPT_FORCE,
) -> None:
    """Generate a new HMAC signing key for evidence manifests."""
    if output and keyring_dir:
        console.print("[red]Provide only one of --output or --keyring-dir[/red]")
        raise typer.Exit(code=2)

    key_bytes = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(key_bytes).decode("ascii").rstrip("=")
    encoded_bytes = f"{encoded}\n".encode("ascii")
    key_id = _key_id_for_bytes(encoded_bytes)

    if keyring_dir:
        keyring_dir.mkdir(parents=True, exist_ok=True)
        output_path = keyring_dir / f"fleetmdm-signing-{key_id}.key"
    elif output:
        output_path = output
    else:
        output_path = Path(f"fleetmdm-signing-{key_id}.key")

    if output_path.exists() and not force:
        console.print("[red]Refusing to overwrite existing key file (use --force)[/red]")
        raise typer.Exit(code=2)

    output_path.write_bytes(encoded_bytes)
    with contextlib.suppress(OSError):
        os.chmod(output_path, 0o600)

    if keyring_dir:
        now = datetime.now(timezone.utc).isoformat()
        manifest_path = _keyring_manifest_path(keyring_dir)
        if manifest_path.exists():
            try:
                manifest = _load_keyring_manifest(manifest_path)
            except (OSError, ValueError) as exc:
                console.print(f"[red]Invalid keyring manifest: {exc}[/red]")
                raise typer.Exit(code=1) from exc
        else:
            manifest = {"schema_version": 1, "created_at": now, "keys": []}

        if any(str(item.get("key_id", "")).strip() == key_id for item in manifest.get("keys", [])):
            console.print(f"[red]key_id already present in keyring manifest: {key_id}[/red]")
            raise typer.Exit(code=1)

        manifest.setdefault("keys", [])
        manifest["keys"] = list(manifest["keys"]) + [
            {
                "key_id": key_id,
                "filename": output_path.name,
                "status": "active",
                "created_at": now,
                "activated_at": now,
                "revoked_at": None,
            }
        ]
        manifest["updated_at"] = now
        _save_keyring_manifest(manifest_path, manifest)

    console.print(f"Wrote signing key to {output_path} (key_id={key_id})")


@evidence_app.command("export")
def evidence_export(
    ctx: typer.Context,
    output: Path | None = OPT_EVIDENCE_OUTPUT,
    redaction_profile: str = OPT_REDACT_PROFILE,
    redact_config: Path | None = OPT_REDACT_CONFIG,
    history_limit: int = OPT_HISTORY_LIMIT,
    signing_key_file: Path | None = OPT_SIGNING_KEY_FILE,
    db: str | None = OPT_DB,
) -> None:
    """Export a SOC-style evidence bundle as JSON artifacts."""
    (
        resolved_output,
        resolved_redaction_profile,
        resolved_history_limit,
    ) = _resolve_evidence_export_defaults(
        output=output,
        redaction_profile=redaction_profile,
        history_limit=history_limit,
        ctx=ctx,
    )
    try:
        profile = _normalize_redaction_profile(resolved_redaction_profile)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    facts_redaction: dict[str, Any] | None = None
    if redact_config:
        try:
            facts_redaction = _load_redact_config(redact_config)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = resolved_output or Path(f"fleetmdm-evidence-{stamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    with connect(db_path) as conn:
        inventory = export_inventory(conn)
        policies: list[dict[str, Any]] = []
        for row in list_policies(conn):
            policy_id = str(row["policy_id"])
            raw_yaml = get_policy_yaml(conn, policy_id) or ""
            raw_yaml_value: str | None
            raw_yaml_redacted = False
            if profile == "none":
                raw_yaml_value = raw_yaml
            elif profile == "minimal":
                raw_yaml_value = _strip_yaml_comment_only_lines(raw_yaml)
            else:
                raw_yaml_value = None
                raw_yaml_redacted = True
            policies.append(
                {
                    "policy_id": policy_id,
                    "name": str(row["name"]),
                    "description": row["description"],
                    "updated_at": str(row["updated_at"]),
                    "raw_yaml": raw_yaml_value,
                    "raw_yaml_redacted": raw_yaml_redacted,
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
        history_excerpt: list[dict[str, Any]] = []
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
        if resolved_history_limit > 0:
            history_excerpt = [
                dict(row)
                for row in list_compliance_history(
                    conn, None, None, resolved_history_limit
                )
            ]

    (
        redacted_inventory,
        redacted_device_assignments,
        redacted_latest_run,
        redacted_drift_changes,
        redacted_history_excerpt,
    ) = _apply_redaction_profile(
        profile,
        inventory,
        device_assignments,
        latest_run,
        drift_changes,
        history_excerpt,
    )
    redacted_inventory = _redact_inventory_facts(redacted_inventory, facts_redaction)

    policies_raw_yaml = "full"
    if profile == "minimal":
        policies_raw_yaml = "comment_stripped"
    elif profile == "strict":
        policies_raw_yaml = "redacted"

    total_artifacts = 7 + (1 if resolved_history_limit > 0 else 0) + (1 if signing_key_file else 0)
    metadata = {
        "generated_at": generated_at,
        "db_path": str(db_path),
        "redaction_profile": profile,
        "policies_raw_yaml": policies_raw_yaml,
        "history_excerpt_limit": resolved_history_limit,
        "history_excerpt_count": len(redacted_history_excerpt),
        "facts_redaction": (
            None
            if not facts_redaction
            else {
                "facts_allowlist": sorted(facts_redaction["facts_allowlist"]),
                "facts_denylist": sorted(facts_redaction["facts_denylist"]),
                "replacement": facts_redaction["replacement"],
                "config_sha256": facts_redaction["config_sha256"],
            }
        ),
        "schema_version": 1,
        "artifact_count": total_artifacts,
    }
    assignments = {"device": redacted_device_assignments, "tag": tag_assignments}

    artifacts = {
        "metadata.json": metadata,
        "inventory.json": redacted_inventory,
        "policies.json": policies,
        "assignments.json": assignments,
        "latest_run.json": redacted_latest_run,
        "drift.json": redacted_drift_changes,
    }
    if resolved_history_limit > 0:
        artifacts["history.json"] = redacted_history_excerpt
    for name, payload in artifacts.items():
        _write_json_artifact(output_dir / name, payload)

    manifest = _build_manifest(output_dir, list(artifacts.keys()), generated_at, profile)
    _write_json_artifact(output_dir / "manifest.json", manifest)

    if signing_key_file:
        manifest_bytes = (output_dir / "manifest.json").read_bytes()
        key_bytes = signing_key_file.read_bytes()
        signature = _sign_manifest(manifest_bytes, key_bytes, generated_at)
        _write_json_artifact(output_dir / "signature.json", signature)

    message = f"Wrote evidence pack to {output_dir} (redaction={profile})"
    if resolved_history_limit > 0:
        message += f", history={len(redacted_history_excerpt)}"
    if signing_key_file:
        message += ", signed"
    console.print(message)


@evidence_app.command("verify")
def evidence_verify(
    bundle_dir: Path = ARG_EVIDENCE_DIR,
    signing_key_file: Path | None = OPT_SIGNING_KEY_FILE,
    keyring_dir: Path | None = OPT_KEYRING_DIR,
    format: str = OPT_VERIFY_FORMAT,
    output: Path | None = OPT_VERIFY_OUTPUT,
) -> None:
    """Verify evidence bundle integrity and optional signature."""
    normalized_format = _normalize_choice_option(format, "--format", ("text", "json"))

    if output and normalized_format != "json":
        console.print("[red]--output is only supported with --format json[/red]")
        raise typer.Exit(code=2)

    if signing_key_file and keyring_dir:
        console.print("[red]Provide only one of --signing-key-file or --keyring-dir[/red]")
        raise typer.Exit(code=2)

    errors: list[str] = []
    warnings: list[str] = []
    artifact_results: list[dict[str, Any]] = []
    bundle_hash_expected: str | None = None
    bundle_hash_actual: str | None = None
    bundle_hash_match: bool | None = None

    signature_path = bundle_dir / "signature.json"
    signature_present = signature_path.exists()
    signature_verified: bool | None = None
    signature_key_id: str | None = None
    signature_key_path: str | None = None
    signature_algorithm: str | None = None
    manifest_sha_expected: str | None = None
    manifest_sha_actual: str | None = None
    manifest_sha_match: bool | None = None
    signature_signed_at: str | None = None
    signature_key_status: str | None = None
    signature_key_created_at: str | None = None
    signature_key_activated_at: str | None = None
    signature_key_revoked_at: str | None = None
    signature_lifecycle_ok: bool | None = None
    signature_lifecycle_errors: list[str] = []
    signature_lifecycle_warnings: list[str] = []

    manifest_path = bundle_dir / "manifest.json"
    manifest_bytes: bytes | None = None
    manifest: dict[str, Any] | None = None

    if not manifest_path.exists():
        errors.append("manifest.json not found in evidence directory")
    else:
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except ValueError as exc:
            errors.append(f"Invalid manifest.json: {exc}")

    entries = None if not manifest else manifest.get("artifacts")
    if manifest and not isinstance(entries, list):
        errors.append("manifest.json is missing a valid artifacts list")
        entries = []

    normalized_entries: list[dict[str, str]] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                errors.append("Invalid manifest entry format")
                continue
            name = str(entry.get("name", ""))
            expected_sha = str(entry.get("sha256", ""))
            expected_size = entry.get("size_bytes")
            if not name or not expected_sha:
                errors.append("Manifest entry missing name or sha256")
                continue

            artifact_path = bundle_dir / name
            record: dict[str, Any] = {
                "name": name,
                "expected_sha256": expected_sha,
                "expected_size_bytes": expected_size if isinstance(expected_size, int) else None,
                "present": artifact_path.exists(),
                "actual_sha256": None,
                "actual_size_bytes": None,
                "checksum_match": None,
                "size_match": None,
                "ok": False,
            }
            if not artifact_path.exists():
                errors.append(f"Missing artifact: {name}")
                artifact_results.append(record)
                continue

            actual_bytes = artifact_path.read_bytes()
            actual_sha = _hash_bytes(actual_bytes)
            record["actual_sha256"] = actual_sha
            record["actual_size_bytes"] = len(actual_bytes)
            record["checksum_match"] = actual_sha == expected_sha
            record["size_match"] = (
                None
                if not isinstance(expected_size, int)
                else bool(expected_size == len(actual_bytes))
            )
            if actual_sha != expected_sha:
                errors.append(f"Checksum mismatch: {name}")
            if isinstance(expected_size, int) and expected_size != len(actual_bytes):
                errors.append(f"Size mismatch: {name}")
            record["ok"] = bool(
                record["checksum_match"]
                and (record["size_match"] is None or record["size_match"] is True)
            )
            artifact_results.append(record)
            normalized_entries.append({"name": name, "sha256": expected_sha})

    expected_bundle_hash = None if not manifest else manifest.get("bundle_sha256")
    if isinstance(expected_bundle_hash, str) and expected_bundle_hash and normalized_entries:
        sorted_entries = sorted(normalized_entries, key=lambda item: item["name"])
        bundle_material = "\n".join(
            f"{entry['name']}:{entry['sha256']}" for entry in sorted_entries
        )
        bundle_hash_expected = expected_bundle_hash
        bundle_hash_actual = sha256_text(bundle_material)
        bundle_hash_match = hmac.compare_digest(bundle_hash_actual, bundle_hash_expected)
        if not bundle_hash_match:
            errors.append("Bundle fingerprint mismatch")

    if signing_key_file or keyring_dir:
        if not signature_present:
            errors.append(
                "signature.json not found, but --signing-key-file was provided"
                if signing_key_file
                else "signature.json not found, but --keyring-dir was provided"
            )
        elif manifest_bytes is None:
            errors.append("manifest.json missing; cannot verify signature")
        else:
            try:
                signature_payload = json.loads(signature_path.read_text(encoding="utf-8"))
            except ValueError as exc:
                errors.append(f"Invalid signature.json: {exc}")
            else:
                signature_algorithm = str(signature_payload.get("algorithm", ""))
                if signature_algorithm != "hmac-sha256":
                    errors.append("Unsupported signature algorithm")

                signature = str(signature_payload.get("signature", ""))
                signature_key_id = str(signature_payload.get("key_id", "")) or None
                signed_at_value = signature_payload.get("signed_at") or signature_payload.get(
                    "generated_at"
                )
                if isinstance(signed_at_value, str) and signed_at_value.strip():
                    signature_signed_at = signed_at_value.strip()
                manifest_sha_expected = str(signature_payload.get("manifest_sha256", "")) or None
                manifest_sha_actual = _hash_bytes(manifest_bytes)
                if manifest_sha_expected:
                    manifest_sha_match = hmac.compare_digest(
                        manifest_sha_actual, manifest_sha_expected
                    )
                    if not manifest_sha_match:
                        errors.append("Manifest SHA256 mismatch")

                selected_key_bytes: bytes | None = None
                key_entry: dict[str, Any] | None = None
                if signing_key_file:
                    selected_key_bytes = signing_key_file.read_bytes()
                    signature_key_path = str(signing_key_file)
                else:
                    desired = signature_key_id
                    if not desired:
                        errors.append(
                            "signature.json missing key_id; cannot select key from keyring"
                        )
                    elif keyring_dir is None:
                        errors.append("Internal error: --keyring-dir missing")
                    else:
                        manifest_path = _keyring_manifest_path(keyring_dir)
                        if manifest_path.exists():
                            try:
                                manifest = _load_keyring_manifest(manifest_path)
                            except (OSError, ValueError) as exc:
                                errors.append(f"Invalid keyring manifest: {exc}")
                            else:
                                manifest_matches = [
                                    entry
                                    for entry in manifest.get("keys", [])
                                    if isinstance(entry, dict)
                                    and str(entry.get("key_id", "")).strip() == desired
                                ]
                                if not manifest_matches:
                                    errors.append(f"No key found in keyring for key_id={desired}")
                                elif len(manifest_matches) > 1:
                                    errors.append(
                                        f"Multiple keys matched in keyring for key_id={desired}"
                                    )
                                else:
                                    key_entry = dict(manifest_matches[0])
                                    filename = str(key_entry.get("filename", "")).strip()
                                    selected = keyring_dir / filename
                                    if not filename or not selected.exists():
                                        errors.append(
                                            "Key entry in manifest missing file "
                                            f"for key_id={desired}"
                                        )
                                    else:
                                        selected_key_bytes = selected.read_bytes()
                                        signature_key_path = str(selected)
                        else:
                            warnings.append(
                                "keyring.json not found; selecting key by scanning directory"
                            )
                            file_matches: list[Path] = []
                            for candidate in sorted(keyring_dir.iterdir()):
                                if not candidate.is_file():
                                    continue
                                try:
                                    if candidate.stat().st_size > 64 * 1024:
                                        continue
                                except OSError:
                                    continue
                                try:
                                    candidate_bytes = candidate.read_bytes()
                                except OSError:
                                    continue
                                if _key_id_for_bytes(candidate_bytes) == desired:
                                    file_matches.append(candidate)
                            if not file_matches:
                                errors.append(f"No key found in keyring for key_id={desired}")
                            elif len(file_matches) > 1:
                                errors.append(
                                    f"Multiple keys matched in keyring for key_id={desired}"
                                )
                            else:
                                selected = file_matches[0]
                                selected_key_bytes = selected.read_bytes()
                                signature_key_path = str(selected)

                if selected_key_bytes is not None:
                    actual_key_id = _key_id_for_bytes(selected_key_bytes)
                    if signature_key_id and actual_key_id != signature_key_id:
                        errors.append("Signing key_id mismatch")

                    # Key lifecycle: validate signature time vs activation/revocation.
                    if key_entry:
                        signature_key_status = str(key_entry.get("status") or "").strip() or None
                        signature_key_created_at = (
                            str(key_entry.get("created_at")).strip()
                            if key_entry.get("created_at")
                            else None
                        )
                        signature_key_activated_at = (
                            str(key_entry.get("activated_at")).strip()
                            if key_entry.get("activated_at")
                            else None
                        )
                        signature_key_revoked_at = (
                            str(key_entry.get("revoked_at")).strip()
                            if key_entry.get("revoked_at")
                            else None
                        )

                        signed_at_dt = _parse_iso8601(signature_signed_at)
                        activated_dt = _parse_iso8601(signature_key_activated_at)
                        revoked_dt = _parse_iso8601(signature_key_revoked_at)
                        if signature_signed_at and signed_at_dt is None:
                            signature_lifecycle_warnings.append(
                                f"Unparseable signature signed_at timestamp: {signature_signed_at}"
                            )
                        if signature_key_activated_at and activated_dt is None:
                            signature_lifecycle_warnings.append(
                                "Unparseable key activated_at timestamp: "
                                f"{signature_key_activated_at}"
                            )
                        if signature_key_revoked_at and revoked_dt is None:
                            signature_lifecycle_warnings.append(
                                "Unparseable key revoked_at timestamp: "
                                f"{signature_key_revoked_at}"
                            )

                        if signed_at_dt and activated_dt and signed_at_dt < activated_dt:
                            signature_lifecycle_errors.append(
                                "Signature timestamp predates key activation"
                            )
                        if signed_at_dt and revoked_dt:
                            if signed_at_dt > revoked_dt:
                                signature_lifecycle_errors.append(
                                    "Signature timestamp is after key revocation"
                                )
                            else:
                                signature_lifecycle_warnings.append(
                                    f"Key was revoked at {signature_key_revoked_at} "
                                    f"(signature signed at {signature_signed_at})"
                                )
                        elif signature_key_status == "revoked" and not signature_key_revoked_at:
                            signature_lifecycle_warnings.append(
                                "Key status is revoked but revoked_at is missing"
                            )

                        signature_lifecycle_ok = len(signature_lifecycle_errors) == 0
                        for item in signature_lifecycle_errors:
                            errors.append(item)
                        warnings.extend(signature_lifecycle_warnings)

                    expected_sig = hmac.new(
                        selected_key_bytes,
                        manifest_bytes,
                        hashlib.sha256,
                    ).hexdigest()
                    signature_verified = hmac.compare_digest(signature, expected_sig)
                    if not signature_verified:
                        errors.append("Manifest signature mismatch")
    elif signature_present and normalized_format == "text":
        console.print("signature.json found; skipping signature verification (no key provided)")

    report = {
        "schema_version": 1,
        "bundle_dir": str(bundle_dir),
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "artifacts": artifact_results,
        "bundle_fingerprint": {
            "expected_sha256": bundle_hash_expected,
            "actual_sha256": bundle_hash_actual,
            "match": bundle_hash_match,
        },
        "signature": {
            "present": signature_present,
            "verified": signature_verified,
            "algorithm": signature_algorithm,
            "key_id": signature_key_id,
            "key_path": signature_key_path,
            "signed_at": signature_signed_at,
            "key_status": signature_key_status,
            "key_created_at": signature_key_created_at,
            "key_activated_at": signature_key_activated_at,
            "key_revoked_at": signature_key_revoked_at,
            "lifecycle_ok": signature_lifecycle_ok,
            "lifecycle_errors": signature_lifecycle_errors,
            "lifecycle_warnings": signature_lifecycle_warnings,
            "manifest_sha256_expected": manifest_sha_expected,
            "manifest_sha256_actual": manifest_sha_actual,
            "manifest_sha256_match": manifest_sha_match,
        },
    }
    if errors:
        report["error"] = {
            "code": "evidence_verify_failed",
            "message": errors[0],
        }

    if normalized_format == "json":
        if output:
            output.write_text(_json_payload_text(report), encoding="utf-8")
        else:
            # Avoid rich wrapping inserting newlines inside long string values.
            typer.echo(_json_payload_text(report), nl=False)
        if errors:
            raise typer.Exit(code=1)
        return

    if errors:
        for error in errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1)

    if signing_key_file or keyring_dir:
        console.print("Evidence bundle integrity and signature verification passed")
        return
    console.print("Evidence bundle integrity verification passed")


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
    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        add_script(conn, script_id, script_name, sha256_text(content), content)
    console.print(f"Saved {script_name} as {script_id}")


@script_app.command("list")
def script_list(
    db: str | None = OPT_DB,
) -> None:
    """List scripts in the catalog."""
    db_path = _resolve_db_path_with_defaults(db)
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

    db_path = _resolve_db_path_with_defaults(db)
    init_db(db_path)
    with connect(db_path) as conn:
        for device in sample_devices:
            if not device.get("last_seen"):
                device["last_seen"] = utc_now()
        ingest_devices(conn, sample_devices)
        policy = load_policy(policy_yaml)
        add_policy(conn, policy.id, policy.name, policy.description, policy_yaml)
    console.print("Seeded sample data")


def main() -> None:
    """Entrypoint for `python -m fleetmdm.cli`."""

    app(prog_name="fleetmdm")


if __name__ == "__main__":
    main()
