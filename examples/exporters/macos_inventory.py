#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import socket
from typing import Any

from _util import emit, parse_tags, run, utc_now_z


def _serial_number() -> str:
    out = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
    if out:
        for line in out.splitlines():
            if "IOPlatformSerialNumber" in line and "=" in line:
                # "IOPlatformSerialNumber" = "C02XYZ123"
                value = line.split("=", 1)[1].strip().strip('"')
                if value:
                    return value
    out = run(["system_profiler", "SPHardwareDataType"])
    if out:
        for line in out.splitlines():
            if "Serial Number" in line and ":" in line:
                value = line.split(":", 1)[1].strip()
                if value:
                    return value
    return "unknown"


def _filevault_enabled() -> bool | None:
    out = run(["fdesetup", "status"])
    if not out:
        return None
    lowered = out.lower()
    if "filevault is on" in lowered:
        return True
    if "filevault is off" in lowered:
        return False
    return None


def _parse_defaults_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    return None


def _read_softwareupdate_defaults() -> dict[str, bool]:
    # Best-effort read of common software update preference keys.
    # These keys may vary by macOS version and local policy; missing keys are omitted.
    domain = "/Library/Preferences/com.apple.SoftwareUpdate"
    keys = {
        "automatic_check_enabled": "AutomaticCheckEnabled",
        "automatic_download": "AutomaticDownload",
        "critical_update_install": "CriticalUpdateInstall",
        "config_data_install": "ConfigDataInstall",
        "auto_install_macos_updates": "AutomaticallyInstallMacOSUpdates",
    }

    updates: dict[str, bool] = {}
    for out_key, pref_key in keys.items():
        raw = run(["defaults", "read", domain, pref_key])
        parsed = _parse_defaults_bool(raw)
        if parsed is None:
            continue
        updates[out_key] = parsed
    return updates


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit FleetMDM inventory JSON (macOS).")
    parser.add_argument("--device-id", default="", help="Override device_id")
    parser.add_argument("--tags", default=None, help="Comma-separated tags (or FLEETMDM_TAGS)")
    args = parser.parse_args()

    hostname = socket.gethostname()
    serial = _serial_number()
    device_id = args.device_id.strip() or serial or hostname
    os_version = platform.mac_ver()[0] or platform.release()

    facts: dict[str, Any] = {
        "cpu": {"cores": os.cpu_count() or 0},
    }
    encrypted = _filevault_enabled()
    if encrypted is not None:
        facts["disk"] = {"encrypted": encrypted}

    updates = _read_softwareupdate_defaults()
    if updates:
        facts["updates"] = updates

    tags = parse_tags(args.tags)
    if tags:
        facts["tags"] = tags

    emit(
        {
            "device_id": device_id,
            "hostname": hostname,
            "os": "macos",
            "os_version": os_version,
            "serial": serial,
            "last_seen": utc_now_z(),
            "facts": facts,
        }
    )


if __name__ == "__main__":
    main()
