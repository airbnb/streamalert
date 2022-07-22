"""A Github site admin tool/action was used."""
from streamalert.shared.rule import rule


@rule(logs=['ghce:cloud'])
def github_cloud_repo_destroyed(rec):
    """
    author:       @BenGallagher-RL
    description:  A repository was permanently destroyed in Github Cloud.
    reference:    https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#:~:text=repo.destroy
    """
    return rec['action'] == "repo.destroy"
