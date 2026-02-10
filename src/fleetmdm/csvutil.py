from __future__ import annotations

from typing import Any

# Spreadsheet programs can interpret some cells as formulas when they begin with these
# characters (even after leading whitespace). Prefixing with a single quote is a common
# mitigation for CSV "formula injection" when users open exports in Excel/Sheets.
_FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if not text:
        return text

    stripped = text.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        return "'" + text
    return text

