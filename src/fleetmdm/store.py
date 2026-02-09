from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = "~/.fleetmdm/fleet.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  os TEXT NOT NULL,
  os_version TEXT NOT NULL,
  serial TEXT NOT NULL,
  last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_facts (
  device_id TEXT PRIMARY KEY,
  facts_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  raw_yaml TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_assignments (
  policy_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  PRIMARY KEY (policy_id, device_id),
  FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policy_tag_assignments (
  policy_id TEXT NOT NULL,
  tag TEXT NOT NULL,
  PRIMARY KEY (policy_id, tag),
  FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scripts (
  script_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  content TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_runs (
  run_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_results (
  run_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  status TEXT NOT NULL,
  failed_checks TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  PRIMARY KEY (run_id, device_id, policy_id),
  FOREIGN KEY (run_id) REFERENCES compliance_runs(run_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
  FOREIGN KEY (policy_id) REFERENCES policies(policy_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_devices_os ON devices(os);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_device ON policy_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_policy_tag_assignments_tag ON policy_tag_assignments(tag);
CREATE INDEX IF NOT EXISTS idx_compliance_results_device ON compliance_results(device_id);
CREATE INDEX IF NOT EXISTS idx_compliance_results_policy ON compliance_results(policy_id);
CREATE INDEX IF NOT EXISTS idx_compliance_runs_started_at ON compliance_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_compliance_results_checked_at ON compliance_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_compliance_results_device_checked_at ON compliance_results(
  device_id, checked_at
);
CREATE INDEX IF NOT EXISTS idx_compliance_results_policy_checked_at ON compliance_results(
  policy_id, checked_at
);
"""


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _normalize_timestamp(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_last_seen(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_db_path(path: str | None) -> Path:
    target = path or DEFAULT_DB_PATH
    expanded = os.path.expanduser(target)
    return Path(expanded)


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def upsert_device(conn: sqlite3.Connection, device: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO devices (device_id, hostname, os, os_version, serial, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          hostname=excluded.hostname,
          os=excluded.os,
          os_version=excluded.os_version,
          serial=excluded.serial,
          last_seen=excluded.last_seen
        """,
        (
            device["device_id"],
            device["hostname"],
            device["os"],
            device["os_version"],
            device["serial"],
            device["last_seen"],
        ),
    )


def upsert_device_facts(
    conn: sqlite3.Connection, device_id: str, facts: dict[str, Any]
) -> None:
    conn.execute(
        """
        INSERT INTO device_facts (device_id, facts_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          facts_json=excluded.facts_json,
          updated_at=excluded.updated_at
        """,
        (device_id, json.dumps(facts), utc_now()),
    )


def add_policy(
    conn: sqlite3.Connection, policy_id: str, name: str, description: str | None, raw_yaml: str
) -> None:
    conn.execute(
        """
        INSERT INTO policies (policy_id, name, description, raw_yaml, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(policy_id) DO UPDATE SET
          name=excluded.name,
          description=excluded.description,
          raw_yaml=excluded.raw_yaml,
          updated_at=excluded.updated_at
        """,
        (policy_id, name, description, raw_yaml, utc_now()),
    )


def list_policies(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT policy_id, name, description, updated_at
        FROM policies
        ORDER BY policy_id
        """
    ).fetchall()


def get_policy(conn: sqlite3.Connection, policy_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT policy_id, name, description, updated_at
        FROM policies
        WHERE policy_id = ?
        """,
        (policy_id,),
    ).fetchone()


def get_policy_yaml(conn: sqlite3.Connection, policy_id: str) -> str | None:
    row = conn.execute("SELECT raw_yaml FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
    if not row:
        return None
    return str(row["raw_yaml"])


def policy_exists(conn: sqlite3.Connection, policy_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM policies WHERE policy_id = ? LIMIT 1",
        (policy_id,),
    ).fetchone()
    return row is not None


def device_exists(conn: sqlite3.Connection, device_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM devices WHERE device_id = ? LIMIT 1", (device_id,)).fetchone()
    return row is not None


def assign_policy(conn: sqlite3.Connection, policy_id: str, device_id: str) -> None:
    conn.execute(
        """
        INSERT INTO policy_assignments (policy_id, device_id)
        VALUES (?, ?)
        ON CONFLICT(policy_id, device_id) DO NOTHING
        """,
        (policy_id, device_id),
    )


def assign_policy_to_tag(conn: sqlite3.Connection, policy_id: str, tag: str) -> None:
    conn.execute(
        """
        INSERT INTO policy_tag_assignments (policy_id, tag)
        VALUES (?, ?)
        ON CONFLICT(policy_id, tag) DO NOTHING
        """,
        (policy_id, tag),
    )


def unassign_policy(conn: sqlite3.Connection, policy_id: str, device_id: str) -> int:
    cur = conn.execute(
        "DELETE FROM policy_assignments WHERE policy_id = ? AND device_id = ?",
        (policy_id, device_id),
    )
    return int(cur.rowcount)


def unassign_policy_from_tag(conn: sqlite3.Connection, policy_id: str, tag: str) -> int:
    cur = conn.execute(
        "DELETE FROM policy_tag_assignments WHERE policy_id = ? AND tag = ?",
        (policy_id, tag),
    )
    return int(cur.rowcount)


def list_policy_assignments_for_device(conn: sqlite3.Connection, device_id: str) -> list[str]:
    return get_assigned_policies(conn, device_id)


def list_policy_assignments_for_tag(conn: sqlite3.Connection, tag: str) -> list[str]:
    rows = conn.execute(
        "SELECT policy_id FROM policy_tag_assignments WHERE tag = ? ORDER BY policy_id",
        (tag,),
    ).fetchall()
    return [str(row["policy_id"]) for row in rows]


def list_all_policy_assignments(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT policy_id, device_id
        FROM policy_assignments
        ORDER BY policy_id, device_id
        """
    ).fetchall()


def list_all_policy_tag_assignments(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT policy_id, tag
        FROM policy_tag_assignments
        ORDER BY policy_id, tag
        """
    ).fetchall()



def get_assigned_policies(conn: sqlite3.Connection, device_id: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT policy_id
        FROM policy_assignments
        WHERE device_id = ?
        ORDER BY policy_id
        """,
        (device_id,),
    ).fetchall()
    return [str(row["policy_id"]) for row in rows]


def get_tag_assigned_policies(conn: sqlite3.Connection, tags: Iterable[str]) -> list[str]:
    tags_list = sorted({tag for tag in tags if tag})
    if not tags_list:
        return []

    rows = conn.execute(
        """
        SELECT DISTINCT policy_id
        FROM policy_tag_assignments
        WHERE tag IN (SELECT value FROM json_each(?))
        ORDER BY policy_id
        """,
        (json.dumps(tags_list),),
    ).fetchall()
    return [str(row["policy_id"]) for row in rows]


def has_any_policy_assignments(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT 1 FROM policy_assignments LIMIT 1").fetchone()
    if row is not None:
        return True
    row = conn.execute("SELECT 1 FROM policy_tag_assignments LIMIT 1").fetchone()
    return row is not None


def resolve_assigned_policies_for_device(
    conn: sqlite3.Connection, device_id: str, tags: Iterable[str]
) -> list[str]:
    direct = get_assigned_policies(conn, device_id)
    by_tag = get_tag_assigned_policies(conn, tags)
    return sorted({*direct, *by_tag})


def list_devices(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT device_id, hostname, os, os_version, serial, last_seen
        FROM devices
        ORDER BY device_id
        """
    ).fetchall()


def get_device(conn: sqlite3.Connection, device_id: str) -> sqlite3.Row | None:
    query = (
        "SELECT device_id, hostname, os, os_version, serial, last_seen "
        "FROM devices WHERE device_id = ?"
    )
    return conn.execute(query, (device_id,)).fetchone()


def get_device_facts(conn: sqlite3.Connection, device_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT facts_json FROM device_facts WHERE device_id = ?", (device_id,)
    ).fetchone()
    if not row:
        return None
    return json.loads(str(row["facts_json"]))


def add_script(
    conn: sqlite3.Connection, script_id: str, name: str, sha256: str, content: str
) -> None:
    conn.execute(
        """
        INSERT INTO scripts (script_id, name, sha256, content, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(script_id) DO UPDATE SET
          name=excluded.name,
          sha256=excluded.sha256,
          content=excluded.content,
          updated_at=excluded.updated_at
        """,
        (script_id, name, sha256, content, utc_now()),
    )


def list_scripts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT script_id, name, sha256, updated_at
        FROM scripts
        ORDER BY script_id
        """
    ).fetchall()


def create_compliance_run(conn: sqlite3.Connection, started_at: str | None = None) -> str:
    normalized_started_at = _normalize_timestamp(started_at) or utc_now()
    run_id = f"run-{normalized_started_at}"
    conn.execute(
        "INSERT INTO compliance_runs (run_id, started_at) VALUES (?, ?)",
        (run_id, normalized_started_at),
    )
    return run_id


def add_compliance_result(
    conn: sqlite3.Connection,
    run_id: str,
    device_id: str,
    policy_id: str,
    policy_name: str,
    status: str,
    failed_checks: str,
    checked_at: str | None = None,
) -> None:
    normalized_checked_at = _normalize_timestamp(checked_at) or utc_now()
    conn.execute(
        """
        INSERT INTO compliance_results (
          run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            device_id,
            policy_id,
            policy_name,
            status,
            failed_checks,
            normalized_checked_at,
        ),
    )


def list_compliance_history(
    conn: sqlite3.Connection,
    device_id: str | None,
    policy_id: str | None,
    limit: int,
    since: str | None = None,
) -> list[sqlite3.Row]:
    normalized_since = _normalize_timestamp(since)

    if device_id and policy_id:
        if normalized_since:
            return conn.execute(
                """
                SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
                FROM compliance_results
                WHERE device_id = ? AND policy_id = ? AND checked_at >= ?
                ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
                LIMIT ?
                """,
                (device_id, policy_id, normalized_since, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE device_id = ? AND policy_id = ?
            ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
            LIMIT ?
            """,
            (device_id, policy_id, limit),
        ).fetchall()

    if device_id:
        if normalized_since:
            return conn.execute(
                """
                SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
                FROM compliance_results
                WHERE device_id = ? AND checked_at >= ?
                ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
                LIMIT ?
                """,
                (device_id, normalized_since, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE device_id = ?
            ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
            LIMIT ?
            """,
            (device_id, limit),
        ).fetchall()

    if policy_id:
        if normalized_since:
            return conn.execute(
                """
                SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
                FROM compliance_results
                WHERE policy_id = ? AND checked_at >= ?
                ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
                LIMIT ?
                """,
                (policy_id, normalized_since, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE policy_id = ?
            ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
            LIMIT ?
            """,
            (policy_id, limit),
        ).fetchall()

    if normalized_since:
        return conn.execute(
            """
            SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE checked_at >= ?
            ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
            LIMIT ?
            """,
            (normalized_since, limit),
        ).fetchall()

    return conn.execute(
        """
        SELECT run_id, device_id, policy_id, policy_name, status, failed_checks, checked_at
        FROM compliance_results
        ORDER BY checked_at DESC, run_id DESC, device_id, policy_id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def list_recent_runs(
    conn: sqlite3.Connection, limit: int, since: str | None = None
) -> list[sqlite3.Row]:
    normalized_since = _normalize_timestamp(since)
    if normalized_since:
        return conn.execute(
            """
            SELECT run_id, started_at
            FROM compliance_runs
            WHERE started_at >= ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (normalized_since, limit),
        ).fetchall()
    return conn.execute(
        "SELECT run_id, started_at FROM compliance_runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()


def list_results_for_run(
    conn: sqlite3.Connection,
    run_id: str,
    policy_id: str | None = None,
    device_id: str | None = None,
) -> list[sqlite3.Row]:
    if policy_id and device_id:
        return conn.execute(
            """
            SELECT device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE run_id = ? AND policy_id = ? AND device_id = ?
            ORDER BY device_id, policy_id
            """,
            (run_id, policy_id, device_id),
        ).fetchall()
    if policy_id:
        return conn.execute(
            """
            SELECT device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE run_id = ? AND policy_id = ?
            ORDER BY device_id, policy_id
            """,
            (run_id, policy_id),
        ).fetchall()
    if device_id:
        return conn.execute(
            """
            SELECT device_id, policy_id, policy_name, status, failed_checks, checked_at
            FROM compliance_results
            WHERE run_id = ? AND device_id = ?
            ORDER BY device_id, policy_id
            """,
            (run_id, device_id),
        ).fetchall()
    return conn.execute(
        """
        SELECT device_id, policy_id, policy_name, status, failed_checks, checked_at
        FROM compliance_results
        WHERE run_id = ?
        ORDER BY device_id, policy_id
        """,
        (run_id,),
    ).fetchall()


def export_inventory(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    devices = list_devices(conn)
    output: list[dict[str, Any]] = []
    for device in devices:
        facts = get_device_facts(conn, str(device["device_id"])) or {}
        output.append(
            {
                "device_id": device["device_id"],
                "hostname": device["hostname"],
                "os": device["os"],
                "os_version": device["os_version"],
                "serial": device["serial"],
                "last_seen": device["last_seen"],
                "facts": facts,
            }
        )
    return output


def ingest_devices(conn: sqlite3.Connection, devices: Iterable[dict[str, Any]]) -> int:
    # Dedupe within a single payload to avoid flip-flopping state when the same device_id appears
    # multiple times. Prefer the newest last_seen; treat missing/blank as "unknown".
    best: dict[str, dict[str, Any]] = {}
    best_seen: dict[str, datetime | None] = {}

    for device in devices:
        device_id = str(device["device_id"])
        candidate = dict(device)
        candidate_seen = _parse_last_seen(candidate.get("last_seen"))

        if device_id not in best:
            best[device_id] = candidate
            best_seen[device_id] = candidate_seen
            continue

        existing_seen = best_seen.get(device_id)
        choose_candidate = False
        if existing_seen is None:
            choose_candidate = True
        elif existing_seen is not None and candidate_seen is not None:
            choose_candidate = candidate_seen >= existing_seen

        if choose_candidate:
            best[device_id] = candidate
            best_seen[device_id] = candidate_seen

    count = 0
    for device_id in sorted(best.keys()):
        device = best[device_id]
        incoming_seen = best_seen.get(device_id)
        if incoming_seen is not None:
            device["last_seen"] = incoming_seen.isoformat()
        else:
            device["last_seen"] = str(device.get("last_seen") or "").strip()

        row = conn.execute(
            "SELECT last_seen FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()

        if row is not None:
            existing_raw = row["last_seen"]
            try:
                existing_seen = _parse_last_seen(existing_raw)
            except ValueError:
                existing_seen = None

            # Do not allow missing/unknown last_seen to overwrite a known last_seen.
            if incoming_seen is None and existing_seen is not None:
                continue
            # Do not allow stale ingests to roll back device state.
            if (
                incoming_seen is not None
                and existing_seen is not None
                and incoming_seen < existing_seen
            ):
                continue

        upsert_device(conn, device)
        upsert_device_facts(conn, device_id, device.get("facts", {}))
        count += 1

    return count
