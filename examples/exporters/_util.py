from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any


def utc_now_z() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_tags(tags_arg: str | None) -> list[str]:
    raw = tags_arg or os.environ.get("FLEETMDM_TAGS", "")
    tags: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        normalized = part.strip().lower()
        if not normalized or normalized in seen:
            continue
        tags.append(normalized)
        seen.add(normalized)
    return tags


def run(cmd: list[str]) -> str | None:
    try:
        proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))

