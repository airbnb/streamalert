"""Improbable Buildkite Rule config """
from stream_alert.shared.rule import rule
from publishers.community.slack.slack_layout import Summary, AttachRuleInfo, \
    AttachPublication, AttachFullRecord


# Remove the @disable decorator to use this rule in a live deployment
@disable
@rule(
    logs=['buildkite:audit_event']
)
def buildkite_admin_granted(rec):
    """
    author:       Improbable CSEC
    description:  Identifies grant of admin rights on buildkite platform
    reference:    https://buildkite.com/organizations/your-org/audit-log
    playbook:     (a) Reach out to the user who granted the permission
                  (b) Link appropriate Jira ticket and close alert.
    """
    return rec['type'] in {'ORGANIZATION_MEMBER_UPDATED',
                           'ORGANIZATION_MEMBER_CREATED'} and rec["data"].get("admin")
