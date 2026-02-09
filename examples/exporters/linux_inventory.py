#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import socket
from typing import Any

from _util import emit, parse_tags, run, utc_now_z


def _read_first(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError:
        return None
    return value or None


def _os_version() -> str:
    # Prefer /etc/os-release VERSION_ID, fall back to PRETTY_NAME, then kernel release.
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return os.uname().release

    parsed: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        parsed[k.strip()] = v.strip().strip('"')
    return parsed.get("VERSION_ID") or parsed.get("PRETTY_NAME") or os.uname().release


def _root_filesystem_encrypted() -> bool | None:
    """
    Best-effort detection of root filesystem encryption.

    Heuristics:
    - If `/` is mounted from a `crypt` (dm-crypt) device, treat as encrypted.
    - If we can't determine the block device reliably (containers, overlayfs), return None.
    """
    source = run(["findmnt", "-n", "-o", "SOURCE", "/"])
    if not source:
        return None
    source = source.strip()
    if not source.startswith("/dev/"):
        return None
    dev_type = (run(["lsblk", "-no", "TYPE", source]) or "").strip().lower()
    if dev_type == "crypt":
        return True
    fs_type = (run(["lsblk", "-no", "FSTYPE", source]) or "").strip().lower()
    if fs_type in {"crypto_luks", "luks"}:
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit FleetMDM inventory JSON (Linux).")
    parser.add_argument("--device-id", default="", help="Override device_id")
    parser.add_argument("--tags", default=None, help="Comma-separated tags (or FLEETMDM_TAGS)")
    args = parser.parse_args()

    hostname = socket.gethostname()
    serial = (
        _read_first("/sys/class/dmi/id/product_serial")
        or _read_first("/etc/machine-id")
        or "unknown"
    )
    device_id = args.device_id.strip() or serial or hostname

    facts: dict[str, Any] = {
        "cpu": {"cores": os.cpu_count() or 0},
        "kernel": {"release": os.uname().release},
    }
    encrypted = _root_filesystem_encrypted()
    if encrypted is not None:
        facts["disk"] = {"encrypted": encrypted}
    tags = parse_tags(args.tags)
    if tags:
        facts["tags"] = tags

    emit(
        {
            "device_id": device_id,
            "hostname": hostname,
            "os": "linux",
            "os_version": _os_version(),
            "serial": serial,
            "last_seen": utc_now_z(),
            "facts": facts,
        }
    )


if __name__ == "__main__":
    main()
