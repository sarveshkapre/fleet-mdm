from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from io import StringIO
from typing import Any
from xml.etree import ElementTree as ET

from rich.console import Console
from rich.table import Table

from fleetmdm.policy import PolicyResult


def render_table(results: Iterable[PolicyResult]) -> str:
    table = Table(title="FleetMDM Compliance")
    table.add_column("Policy")
    table.add_column("Status")
    table.add_column("Failed Checks")

    for result in results:
        failed = [check.message for check in result.checks if not check.passed]
        status = "PASS" if result.passed else "FAIL"
        table.add_row(result.policy_name, status, "; ".join(failed))

    console = Console(record=True)
    console.print(table)
    return console.export_text()


def render_json(results: Iterable[PolicyResult]) -> str:
    payload = []
    for result in results:
        payload.append(
            {
                "policy_id": result.policy_id,
                "policy_name": result.policy_name,
                "passed": result.passed,
                "checks": [
                    {
                        "key": check.key,
                        "op": check.op,
                        "value": check.value,
                        "passed": check.passed,
                        "message": check.message,
                    }
                    for check in result.checks
                ],
            }
        )
    return json.dumps(payload, indent=2)


def render_csv(results: Iterable[PolicyResult]) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["policy_id", "policy_name", "status", "failed_checks"])
    for result in results:
        failed = [check.message for check in result.checks if not check.passed]
        writer.writerow(
            [
                result.policy_id,
                result.policy_name,
                "PASS" if result.passed else "FAIL",
                "; ".join(failed),
            ]
        )
    return buffer.getvalue()


def render_junit_summary(summary: Iterable[dict[str, Any]]) -> str:
    """
    Render a minimal JUnit XML document for CI/compliance pipeline ingestion.

    Each policy becomes a testcase. Any policy with a non-zero failed_count is a failed testcase.
    """
    rows = list(summary)
    failures = sum(1 for row in rows if int(row.get("failed_count", 0) or 0) > 0)
    skipped = sum(
        1
        for row in rows
        if int(row.get("failed_count", 0) or 0) == 0 and int(row.get("passed_count", 0) or 0) == 0
    )

    suite = ET.Element(
        "testsuite",
        attrib={
            "name": "FleetMDM Compliance Summary",
            "tests": str(len(rows)),
            "failures": str(failures),
            "skipped": str(skipped),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    for row in rows:
        policy_id = str(row.get("policy_id", ""))
        policy_name = str(row.get("policy_name", ""))
        passed = int(row.get("passed_count", 0) or 0)
        failed = int(row.get("failed_count", 0) or 0)

        case = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "name": policy_id or policy_name or "policy",
                "classname": "fleetmdm.policy",
                "time": "0",
            },
        )

        if policy_name and policy_name != policy_id:
            ET.SubElement(case, "system-out").text = f"policy_name={policy_name}"

        if failed > 0:
            failure = ET.SubElement(
                case,
                "failure",
                attrib={"message": f"failed_devices={failed} passed_devices={passed}"},
            )
            failure.text = f"Policy {policy_id or policy_name} failed on {failed} device(s)."
        elif passed == 0 and failed == 0:
            ET.SubElement(case, "skipped", attrib={"message": "no applicable devices"})

    xml_bytes = ET.tostring(suite, encoding="utf-8", xml_declaration=True)
    return f"{xml_bytes.decode('utf-8')}\n"
