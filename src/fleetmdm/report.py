from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from io import StringIO

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
