from textwrap import dedent

from fleetmdm.policy import evaluate_policy, load_policy


def test_policy_eval_pass() -> None:
    policy_yaml = dedent(
        """
        id: disk-encryption
        name: Disk Encryption Enabled
        checks:
          - key: disk.encrypted
            op: eq
            value: true
          - key: os_version
            op: version_gte
            value: "14.0"
        """
    ).strip()

    policy = load_policy(policy_yaml)
    facts = {"disk": {"encrypted": True}, "os_version": "14.4"}
    result = evaluate_policy(policy, facts)

    assert result.passed is True
    assert all(check.passed for check in result.checks)


def test_policy_eval_missing_fact() -> None:
    policy_yaml = dedent(
        """
        id: cpu-check
        name: CPU Check
        checks:
          - key: cpu.cores
            op: gte
            value: 4
        """
    ).strip()

    policy = load_policy(policy_yaml)
    facts = {"disk": {"encrypted": True}}
    result = evaluate_policy(policy, facts)

    assert result.passed is False
    assert result.checks[0].passed is False
