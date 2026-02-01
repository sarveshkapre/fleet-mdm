from textwrap import dedent

from fleetmdm.policy import load_policy, policy_matches_targets


def test_policy_targets_match() -> None:
    policy_yaml = dedent(
        """
        id: disk-encryption
        name: Disk Encryption Enabled
        targets:
          os: [macos, linux]
          tags: prod
        checks:
          - key: disk.encrypted
            op: eq
            value: true
        """
    ).strip()
    policy = load_policy(policy_yaml)
    device = {"os": "macos"}
    facts = {"tags": ["prod", "design"]}

    assert policy_matches_targets(policy, device, facts) is True


def test_policy_targets_miss() -> None:
    policy_yaml = dedent(
        """
        id: disk-encryption
        name: Disk Encryption Enabled
        targets:
          os: linux
          tags: [prod]
        checks:
          - key: disk.encrypted
            op: eq
            value: true
        """
    ).strip()
    policy = load_policy(policy_yaml)
    device = {"os": "macos"}
    facts = {"tags": ["design"]}

    assert policy_matches_targets(policy, device, facts) is False
