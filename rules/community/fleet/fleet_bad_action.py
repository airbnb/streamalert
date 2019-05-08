from stream_alert.shared.rule import rule
# Remove disable import if no rules are disabled using the @disable decorator.
from stream_alert.shared.rule import disable

# Remove the @disable decorator to use this rule in a live deployment
@disable
@rule(
    logs=['fleet:results']
)
def fleet_bad_action(rec):
    """
    author:       gavinelder
    description:  Alert when a user carries out a bad action.
    reference:    https://
    playbook:     (a) Reach out to the user who made the modification and confirm intent.
                  (b) Link appropriate Jira ticket.
    """
    return (
        '1' == rec['columns'].get('bad_action', '1')
    )
