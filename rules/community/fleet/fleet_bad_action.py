from stream_alert.shared.rule import rule
from stream_alert.shared.rule import disable
from publishers.community.slack.slack_layout import Summary, AttachRuleInfo \
        , AttachPublication, AttachFullRecord

@disable
@rule(
    logs=['fleet:results'],
    publishers=[
        Summary,           # Prints the first rausch colored section
        AttachRuleInfo,    # Prints the 2nd lima colored section
        AttachPublication, # Prints the babu/cyan colored section
        AttachFullRecord,  # Prints the hackberry colored section
    ]
)
def osquery_batch_puppet_disabled(rec):
    """
    author:       coresec
    description:  Alert when puppet is set to disabled on a users device.
    reference:    https://brevi.link/puppet-disabled
    playbook:     (a) Reach out to the user who made the modification and confirm intent.
                  (b) Link appropriate Jira ticket.
                  (c) Re-Enable puppet.
    """
    return (
        '1' in rec['columns']['bad_action']
    )
