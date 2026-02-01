from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml
from packaging import version
from pydantic import BaseModel, Field, ValidationError


class PolicyCheck(BaseModel):
    key: str
    op: str
    value: Any
    message: str | None = None


class Policy(BaseModel):
    id: str = Field(..., description="Policy identifier")
    name: str
    description: str | None = None
    targets: dict[str, Any] | None = None
    checks: list[PolicyCheck]


@dataclass
class CheckResult:
    key: str
    op: str
    value: Any
    passed: bool
    message: str


@dataclass
class PolicyResult:
    policy_id: str
    policy_name: str
    passed: bool
    checks: list[CheckResult]


ALLOWED_OPS = {
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "contains",
    "in",
    "not_in",
    "regex",
    "version_gte",
    "version_lte",
}


def load_policy(raw_yaml: str) -> Policy:
    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a mapping")
    policy = Policy.model_validate(data)
    for check in policy.checks:
        if check.op not in ALLOWED_OPS:
            raise ValueError(f"Unsupported op: {check.op}")
    return policy


def load_policy_from_file(path: str) -> tuple[Policy, str]:
    with open(path, encoding="utf-8") as handle:
        raw_yaml = handle.read()
    return load_policy(raw_yaml), raw_yaml


def get_fact_value(facts: dict[str, Any], key: str) -> Any:
    current: Any = facts
    for part in key.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _compare_values(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op in {"lt", "lte", "gt", "gte"}:
        left_num = _as_number(left)
        right_num = _as_number(right)
        if left_num is not None and right_num is not None:
            if op == "lt":
                return left_num < right_num
            if op == "lte":
                return left_num <= right_num
            if op == "gt":
                return left_num > right_num
            return left_num >= right_num
        left_str = str(left)
        right_str = str(right)
        if op == "lt":
            return left_str < right_str
        if op == "lte":
            return left_str <= right_str
        if op == "gt":
            return left_str > right_str
        return left_str >= right_str
    if op == "contains":
        if isinstance(left, (list, tuple, set)):
            return right in left
        return str(right) in str(left)
    if op == "in":
        if isinstance(right, (list, tuple, set)):
            return left in right
        return False
    if op == "not_in":
        if isinstance(right, (list, tuple, set)):
            return left not in right
        return False
    if op == "regex":
        return bool(re.search(str(right), str(left)))
    if op == "version_gte":
        return version.parse(str(left)) >= version.parse(str(right))
    if op == "version_lte":
        return version.parse(str(left)) <= version.parse(str(right))
    raise ValueError(f"Unknown operator: {op}")


def evaluate_policy(policy: Policy, facts: dict[str, Any]) -> PolicyResult:
    check_results: list[CheckResult] = []
    all_passed = True
    for check in policy.checks:
        fact_value = get_fact_value(facts, check.key)
        if fact_value is None:
            passed = False
            message = f"missing fact: {check.key}"
        else:
            try:
                passed = _compare_values(check.op, fact_value, check.value)
                message = check.message or f"{check.key} {check.op} {check.value}"
            except Exception as exc:  # pragma: no cover - defensive
                passed = False
                message = f"error: {exc}"
        if not passed:
            all_passed = False
        check_results.append(
            CheckResult(
                key=check.key,
                op=check.op,
                value=check.value,
                passed=passed,
                message=message,
            )
        )
    return PolicyResult(policy.id, policy.name, all_passed, check_results)


def validate_policy_file(path: str) -> list[str]:
    try:
        load_policy_from_file(path)
        return []
    except (ValueError, ValidationError) as exc:
        return [str(exc)]
