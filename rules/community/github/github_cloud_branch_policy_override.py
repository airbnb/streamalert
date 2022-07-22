"""A Github site admin tool/action was used."""
from streamalert.shared.rule import rule


@rule(logs=['ghe:cloud'])
def github_cloud_branch_policy_override(rec):
    """
    author:       @BenGallagher-RL
    description:  A protected branch policy was overridden.
    reference:    https://docs.github.com/en/enterprise-server@3.2/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#:~:text=protected_branch.policy_override
    """
    return rec['action'] == "protected_branch.policy_override"
