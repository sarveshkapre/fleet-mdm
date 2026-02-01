from pathlib import Path

import pytest
from pydantic import ValidationError

from fleetmdm.inventory import load_inventory_json


def test_inventory_load_object(tmp_path: Path) -> None:
    path = tmp_path / "device.json"
    path.write_text(
        """
        {
          "device_id": "mac-001",
          "hostname": "studio-1",
          "os": "macos",
          "os_version": "14.4",
          "serial": "C02XYZ123",
          "facts": {"tags": ["prod"]}
        }
        """.strip(),
        encoding="utf-8",
    )
    devices = load_inventory_json(path)
    assert devices[0]["device_id"] == "mac-001"
    assert devices[0]["last_seen"] == ""


def test_inventory_load_rejects_extra_fields(tmp_path: Path) -> None:
    path = tmp_path / "device.json"
    path.write_text(
        """
        {
          "device_id": "mac-001",
          "hostname": "studio-1",
          "os": "macos",
          "os_version": "14.4",
          "serial": "C02XYZ123",
          "facts": {},
          "unexpected": true
        }
        """.strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_inventory_json(path)

