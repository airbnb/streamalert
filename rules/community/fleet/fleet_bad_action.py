from stream_alert.shared.rule import rule
from stream_alert.shared.rule import disable


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
