from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class DeviceInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    os: str = Field(..., min_length=1)
    os_version: str = Field(..., min_length=1)
    serial: str = Field(..., min_length=1)
    last_seen: str | None = None
    facts: dict[str, Any] = Field(default_factory=dict)


_DEVICE_LIST = TypeAdapter(list[DeviceInventory])
_DEVICE_SINGLE = TypeAdapter(DeviceInventory)


def parse_last_seen(value: str | None) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid last_seen timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_last_seen(value: str | None) -> str:
    dt = parse_last_seen(value)
    if dt is None:
        return ""
    return dt.isoformat()


def load_inventory_json(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    devices: list[DeviceInventory]
    if isinstance(raw, list):
        devices = _DEVICE_LIST.validate_python(raw)
    elif isinstance(raw, dict):
        devices = [_DEVICE_SINGLE.validate_python(raw)]
    else:
        raise ValueError("JSON must be an object or list")

    normalized: list[dict[str, Any]] = []
    for device in devices:
        payload = device.model_dump()
        payload["last_seen"] = normalize_last_seen(payload.get("last_seen"))
        normalized.append(payload)
    return normalized


def inventory_json_schema() -> dict[str, Any]:
    return DeviceInventory.model_json_schema()
